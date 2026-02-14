//
//  GSAAuthenticator.swift
//  ApplePackage
//
//  Created by Codex on 2026/2/14.
//

import Foundation
import Security

enum GSAAuthenticator {
    private static let gsaEndpoint: URL = .init(string: "https://gsa.apple.com/grandslam/GsService2")!
    private static let validateEndpoint: URL = .init(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
    private static let trustedDeviceEndpoint: URL = .init(string: "https://gsa.apple.com/auth/verify/trusteddevice")!
    private static let authEndpoint: URL = .init(string: "https://gsa.apple.com/auth")!
    private static let verifyPhoneEndpoint: URL = .init(string: "https://gsa.apple.com/auth/verify/phone/")!
    private static let verifyPhoneSecurityCodeEndpoint: URL = .init(string: "https://gsa.apple.com/auth/verify/phone/securitycode")!

    private static let gsaUserAgent: String = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

    private final class NoRedirectURLSessionDelegate: NSObject, URLSessionTaskDelegate {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest,
            completionHandler: @escaping (URLRequest?) -> Void
        ) {
            completionHandler(nil)
        }
    }

    private static let noRedirectDelegate = NoRedirectURLSessionDelegate()

    private static let urlSession: URLSession = {
        let conf = URLSessionConfiguration.ephemeral
        conf.requestCachePolicy = .reloadIgnoringLocalCacheData
        conf.urlCache = nil
        conf.httpShouldSetCookies = false
        return URLSession(configuration: conf, delegate: noRedirectDelegate, delegateQueue: nil)
    }()

    static func authenticate(email: String, password: String, code: String) async throws -> Account {
        let anisetteProvider = RemoteAnisetteDataProvider(serverURL: Configuration.anisetteServerURL)

        // First attempt: password SRP.
        var session = try await loginEmailPassword(email: email, password: password, anisetteProvider: anisetteProvider)
        switch session.state {
        case .loggedIn:
            break
        case .needsTrustedDevice2FA:
            _ = try? await send2FAToTrustedDevices(session: session, anisetteProvider: anisetteProvider)
            guard !code.isEmpty else {
                throw AuthenticationError.twoFactorRequired("""
                Authentication requires verification code.
                If no verification code prompted, try logging in at https://account.apple.com to trigger the alert, then fill the 2FA Code field.
                """)
            }
            try await verifyTrustedDevice2FA(code: code, session: session, anisetteProvider: anisetteProvider)
            session = try await loginEmailPassword(email: email, password: password, anisetteProvider: anisetteProvider)
        case .needsSMS2FA:
            let verifyBody = try await sendSMS2FAToTrustedPhone(session: session, anisetteProvider: anisetteProvider)
            guard !code.isEmpty else {
                throw AuthenticationError.twoFactorRequired("""
                Authentication requires SMS verification code.
                Request the code on your Apple ID sign-in prompt, then fill the 2FA Code field.
                """)
            }
            try await verifySMS2FA(code: code, verifyBody: verifyBody, session: session, anisetteProvider: anisetteProvider)
            session = try await loginEmailPassword(email: email, password: password, anisetteProvider: anisetteProvider)
        case let .needsExtraStep(step):
            throw AuthenticationError.gsaMalformedResponse("additional authentication step required: \(step)")
        }

        guard case .loggedIn = session.state else {
            throw AuthenticationError.gsaMalformedResponse("unexpected login state")
        }

        return try buildAccount(
            email: email,
            password: password,
            spd: session.spd
        )
    }

    // MARK: - Login (SRP)

    private struct GSASPD: Sendable {
        let dsid: String
        let idmsToken: String
        let firstName: String
        let lastName: String
        let passwordToken: String?
        let storeFront: String?
    }

    private struct LoginSession: Sendable {
        enum State: Sendable {
            case loggedIn
            case needsTrustedDevice2FA
            case needsSMS2FA
            case needsExtraStep(String)
        }

        let spd: GSASPD
        let state: State
    }

    private static func loginEmailPassword(
        email: String,
        password: String,
        anisetteProvider: RemoteAnisetteDataProvider
    ) async throws -> LoginSession {
        let srp = SrpClient(group: SrpGroups.rfc5054_2048)

        let a = try randomBytes(count: 32)
        let aPub = srp.computePublicEphemeral(a: a)

        let anisette = try await anisetteProvider.anisetteData()

        var headers: [String: String] = [
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": gsaUserAgent,
        ]
        if let clientInfo = anisette.headerValue(for: "X-Mme-Client-Info") {
            headers["X-MMe-Client-Info"] = clientInfo
        }

        let cpd = try anisette.toPlistDictionary(cpd: true, clientInfo: false, appInfo: false)

        let initRequest: [String: Any] = [
            "Header": [
                "Version": "1.0.1",
            ],
            "Request": [
                "A2k": aPub,
                "cpd": cpd,
                "o": "init",
                "ps": ["s2k", "s2k_fo"],
                "u": email,
            ],
        ]

        let initResponse = try await sendPlistRequest(url: gsaEndpoint, method: "POST", headers: headers, body: initRequest)
        try checkGSAError(initResponse)

        guard let salt = initResponse["s"] as? Data,
              let bPub = initResponse["B"] as? Data,
              let itersAny = initResponse["i"],
              let c = initResponse["c"] as? String
        else {
            throw AuthenticationError.gsaMalformedResponse("missing init parameters")
        }

        let iters: Int = {
            if let v = itersAny as? Int { return v }
            if let v = itersAny as? Int64 { return Int(v) }
            if let v = itersAny as? NSNumber { return v.intValue }
            return 0
        }()
        guard iters > 0 else {
            throw AuthenticationError.gsaMalformedResponse("invalid iterations")
        }

        let protocolName = initResponse["sp"] as? String ?? "s2k"
        let passwordKey = try derivePasswordKey(password: password, salt: salt, iterations: iters, protocolName: protocolName)

        let verifier = try srp.processReply(
            a: a,
            username: Data(email.utf8),
            password: passwordKey,
            salt: salt,
            bPub: bPub
        )

        let completeRequest: [String: Any] = [
            "Header": [
                "Version": "1.0.1",
            ],
            "Request": [
                "M1": verifier.m1,
                "cpd": cpd,
                "c": c,
                "o": "complete",
                "u": email,
            ],
        ]

        let completeResponse = try await sendPlistRequest(url: gsaEndpoint, method: "POST", headers: headers, body: completeRequest)
        try checkGSAError(completeResponse)

        guard let m2 = completeResponse["M2"] as? Data else {
            throw AuthenticationError.gsaMalformedResponse("missing server proof")
        }
        try verifier.verifyServerProof(m2)

        guard let spdEncrypted = completeResponse["spd"] as? Data else {
            throw AuthenticationError.gsaMalformedResponse("missing spd")
        }

        let spdDict = try decryptSPD(spdEncrypted, sessionKey: verifier.key)
        let spd = try decodeSPD(spdDict)

        let state: LoginSession.State = {
            if let status = completeResponse["Status"] as? [String: Any],
               let au = status["au"] as? String
            {
                switch au {
                case "trustedDeviceSecondaryAuth":
                    return .needsTrustedDevice2FA
                case "secondaryAuth":
                    return .needsSMS2FA
                default:
                    return .needsExtraStep(au)
                }
            }
            return .loggedIn
        }()

        return LoginSession(spd: spd, state: state)
    }

    private static func derivePasswordKey(
        password: String,
        salt: Data,
        iterations: Int,
        protocolName: String
    ) throws -> Data {
        let hashed = Crypto.sha256(Data(password.utf8))
        let pbkdfPassword: Data
        if protocolName == "s2k_fo" {
            pbkdfPassword = Data(hashed.hexLowercased.utf8)
        } else {
            pbkdfPassword = hashed
        }
        return try Crypto.pbkdf2SHA256(password: pbkdfPassword, salt: salt, iterations: iterations, keyLength: 32)
    }

    private static func decryptSPD(_ ciphertext: Data, sessionKey: Data) throws -> [String: Any] {
        let extraDataKey = Crypto.hmacSHA256(key: sessionKey, message: Data("extra data key:".utf8))
        let extraDataIVFull = Crypto.hmacSHA256(key: sessionKey, message: Data("extra data iv:".utf8))
        let iv = extraDataIVFull.prefix(16)
        let plaintext = try Crypto.aes256CbcDecryptPkcs7(ciphertext, key: extraDataKey, iv: Data(iv))
        let plist = try PropertyListSerialization.propertyList(from: plaintext, options: [], format: nil)
        guard let dict = plist as? [String: Any] else {
            throw AuthenticationError.gsaMalformedResponse("invalid spd")
        }
        return dict
    }

    private static func decodeSPD(_ spd: [String: Any]) throws -> GSASPD {
        guard let dsid = spd["adsid"] as? String, !dsid.isEmpty else {
            throw AuthenticationError.gsaMalformedResponse("missing adsid")
        }
        guard let token = spd["GsIdmsToken"] as? String, !token.isEmpty else {
            throw AuthenticationError.gsaMalformedResponse("missing GsIdmsToken")
        }

        let firstName = (spd["fn"] as? String) ?? ""
        let lastName = (spd["ln"] as? String) ?? ""
        let passwordToken = extractPasswordToken(from: spd)
        let storeFront = resolveStoreFront(from: spd)

        return GSASPD(
            dsid: dsid,
            idmsToken: token,
            firstName: firstName,
            lastName: lastName,
            passwordToken: passwordToken,
            storeFront: storeFront
        )
    }

    // MARK: - 2FA

    private struct AuthenticationExtras: Decodable, Sendable {
        struct TrustedPhoneNumber: Decodable, Sendable {
            let id: Int
            let numberWithDialCode: String?
            let lastTwoDigits: String?
            let pushMode: String?
        }

        let trustedPhoneNumbers: [TrustedPhoneNumber]
    }

    private struct VerifyBody: Encodable, Sendable {
        struct PhoneNumber: Encodable, Sendable {
            let id: Int
        }

        struct SecurityCode: Encodable, Sendable {
            let code: String
        }

        let phoneNumber: PhoneNumber
        let mode: String
        var securityCode: SecurityCode?
    }

    private static func send2FAToTrustedDevices(
        session: LoginSession,
        anisetteProvider: RemoteAnisetteDataProvider
    ) async throws {
        let headers = try await build2FAHeaders(session: session, anisetteProvider: anisetteProvider, sms: false)
        _ = try await sendRawRequest(url: trustedDeviceEndpoint, method: "GET", headers: headers, body: nil)
    }

    private static func verifyTrustedDevice2FA(
        code: String,
        session: LoginSession,
        anisetteProvider: RemoteAnisetteDataProvider
    ) async throws {
        var headers = try await build2FAHeaders(session: session, anisetteProvider: anisetteProvider, sms: false)
        headers["security-code"] = code

        let data = try await sendRawRequest(url: validateEndpoint, method: "GET", headers: headers, body: nil)
        let dict = try parsePlistResponse(data)
        try checkGSAError(dict)
    }

    private static func sendSMS2FAToTrustedPhone(
        session: LoginSession,
        anisetteProvider: RemoteAnisetteDataProvider
    ) async throws -> VerifyBody {
        let extras = try await getAuthExtras(session: session, anisetteProvider: anisetteProvider)
        guard let phone = extras.trustedPhoneNumbers.first else {
            throw AuthenticationError.gsaMalformedResponse("no trusted phone numbers")
        }

        let body = VerifyBody(phoneNumber: .init(id: phone.id), mode: "sms", securityCode: nil)
        let headers = try await build2FAHeaders(session: session, anisetteProvider: anisetteProvider, sms: true)
        let payload = try JSONEncoder().encode(body)
        // Apple currently rejects PUT here (Allow: GET, POST, OPTIONS).
        _ = try await sendRawRequest(url: verifyPhoneEndpoint, method: "POST", headers: headers, body: payload)
        return body
    }

    private static func verifySMS2FA(
        code: String,
        verifyBody: VerifyBody,
        session: LoginSession,
        anisetteProvider: RemoteAnisetteDataProvider
    ) async throws {
        var body = verifyBody
        body.securityCode = .init(code: code)

        var headers = try await build2FAHeaders(session: session, anisetteProvider: anisetteProvider, sms: true)
        headers["Accept"] = "application/json"

        let payload = try JSONEncoder().encode(body)
        do {
            _ = try await sendRawRequest(url: verifyPhoneSecurityCodeEndpoint, method: "POST", headers: headers, body: payload)
        } catch {
            throw AuthenticationError.invalidTwoFactorCode
        }
    }

    private static func getAuthExtras(
        session: LoginSession,
        anisetteProvider: RemoteAnisetteDataProvider
    ) async throws -> AuthenticationExtras {
        var headers = try await build2FAHeaders(session: session, anisetteProvider: anisetteProvider, sms: true)
        headers["Accept"] = "application/json"

        // Apple may return HTTP 423 with a JSON body describing trusted phone numbers.
        // Treat it as a valid response so we can continue the SMS 2FA flow.
        let data = try await sendRawRequest(
            url: authEndpoint,
            method: "GET",
            headers: headers,
            body: nil,
            acceptableStatusCodes: [201, 423]
        )
        return try JSONDecoder().decode(AuthenticationExtras.self, from: data)
    }

    private static func build2FAHeaders(
        session: LoginSession,
        anisetteProvider: RemoteAnisetteDataProvider,
        sms: Bool
    ) async throws -> [String: String] {
        let identityToken = Data("\(session.spd.dsid):\(session.spd.idmsToken)".utf8).base64EncodedString()

        let anisette = try await anisetteProvider.anisetteData()
        let anisetteHeaders = try anisette.generateHeaders(cpd: false, clientInfo: true, appInfo: true)

        var headers: [String: String] = [:]
        for (k, v) in anisetteHeaders {
            headers[k] = v
        }

        if !sms {
            headers["Content-Type"] = "text/x-xml-plist"
            headers["Accept"] = "text/x-xml-plist"
        } else {
            headers["Content-Type"] = "application/json"
        }

        headers["User-Agent"] = "Xcode"
        headers["Accept-Language"] = "en-us"
        headers["X-Apple-Identity-Token"] = identityToken

        if let loc = anisette.headerValue(for: "X-Apple-Locale") {
            headers["Loc"] = loc
        }

        return headers
    }

    // MARK: - Account

    private static func buildAccount(
        email: String,
        password: String,
        spd: GSASPD
    ) throws -> Account {
        guard let passwordToken = spd.passwordToken, !passwordToken.isEmpty else {
            throw AuthenticationError.gsaMalformedResponse("missing token")
        }
        let store = spd.storeFront ?? resolveStoreFront(from: [:])

        return Account(
            email: email,
            password: password,
            appleId: email,
            store: store,
            firstName: spd.firstName,
            lastName: spd.lastName,
            passwordToken: passwordToken,
            directoryServicesIdentifier: spd.dsid,
            cookie: []
        )
    }

    private static func resolveStoreFront(from spd: [String: Any]) -> String {
        if let store = spd["sf"] as? String, !store.isEmpty {
            return store
        }
        if let store = spd["storeFront"] as? String, !store.isEmpty {
            return store
        }

        let region = Locale.current.regionCode ?? "US"
        return Configuration.storeId(for: region) ?? "143441"
    }

    private static func extractPasswordToken(from spd: [String: Any]) -> String? {
        // Best-effort: try PET token first (commonly present in spd["t"]).
        if let t = spd["t"] as? [String: Any],
           let pet = t["com.apple.gs.idms.pet"] as? [String: Any],
           let token = pet["token"] as? String
        {
            return token
        }

        // Fallback: try a few common token keys.
        if let token = spd["token"] as? String { return token }
        if let token = spd["passwordToken"] as? String { return token }

        return nil
    }

    // MARK: - Networking

    private static func sendPlistRequest(
        url: URL,
        method: String,
        headers: [String: String],
        body: [String: Any]
    ) async throws -> [String: Any] {
        let data = try PropertyListSerialization.data(fromPropertyList: body, format: .xml, options: 0)
        let raw = try await sendRawRequest(url: url, method: method, headers: headers, body: data)
        let dict = try parsePlistResponse(raw)

        guard let response = dict["Response"] as? [String: Any] else {
            throw AuthenticationError.gsaMalformedResponse("missing Response")
        }
        return response
    }

    private static func sendRawRequest(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?,
        acceptableStatusCodes: Set<Int> = []
    ) async throws -> Data {
        try await sendRawRequest(
            url: url,
            method: method,
            headers: headers,
            body: body,
            acceptableStatusCodes: acceptableStatusCodes,
            redirectCount: 0,
            slashRetry: false
        )
    }

    private static func sendRawRequest(
        url: URL,
        method: String,
        headers: [String: String],
        body: Data?,
        acceptableStatusCodes: Set<Int>,
        redirectCount: Int,
        slashRetry: Bool
    ) async throws -> Data {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.httpBody = body
        req.cachePolicy = .reloadIgnoringLocalCacheData
        req.timeoutInterval = 30

        for (k, v) in headers {
            req.setValue(v, forHTTPHeaderField: k)
        }

        let (data, response) = try await urlSession.data(for: req)
        if let http = response as? HTTPURLResponse {
            if (300...399).contains(http.statusCode) {
                guard redirectCount < 3 else {
                    throw AuthenticationError.gsaMalformedResponse("too many redirects (\(http.statusCode)) for \(method) \(url.absoluteString)")
                }

                guard let location = http.value(forHTTPHeaderField: "Location"),
                      let nextURL = URL(string: location, relativeTo: url)?.absoluteURL
                else {
                    throw AuthenticationError.gsaMalformedResponse("redirect (\(http.statusCode)) without Location for \(method) \(url.absoluteString)")
                }

                let nextMethod: String
                let nextBody: Data?
                if http.statusCode == 303 {
                    nextMethod = "GET"
                    nextBody = nil
                } else {
                    nextMethod = method
                    nextBody = body
                }

                return try await sendRawRequest(
                    url: nextURL,
                    method: nextMethod,
                    headers: headers,
                    body: nextBody,
                    acceptableStatusCodes: acceptableStatusCodes,
                    redirectCount: redirectCount + 1,
                    slashRetry: slashRetry
                )
            }

            if http.statusCode == 405, !slashRetry, !url.path.hasSuffix("/") {
                var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
                if var path = comps?.path, !path.hasSuffix("/") {
                    path.append("/")
                    comps?.path = path
                }
                if let retryURL = comps?.url {
                    return try await sendRawRequest(
                        url: retryURL,
                        method: method,
                        headers: headers,
                        body: body,
                        acceptableStatusCodes: acceptableStatusCodes,
                        redirectCount: redirectCount,
                        slashRetry: true
                    )
                }
            }

            if !(200...299).contains(http.statusCode), !acceptableStatusCodes.contains(http.statusCode) {
                let allow = http.value(forHTTPHeaderField: "Allow")
                let location = http.value(forHTTPHeaderField: "Location")
                let correlationKey = http.value(forHTTPHeaderField: "X-Apple-Jingle-Correlation-Key")
                    ?? http.value(forHTTPHeaderField: "x-apple-jingle-correlation-key")

                let bodySnippet: String = {
                    guard !data.isEmpty else { return "<empty>" }
                    if let str = String(data: data, encoding: .utf8) {
                        return String(str.prefix(200))
                    }
                    return "<\(data.count) bytes>"
                }()

                var parts: [String] = []
                parts.append("HTTP \(http.statusCode) for \(method) \(url.absoluteString)")
                if let allow, !allow.isEmpty { parts.append("Allow: \(allow)") }
                if let location, !location.isEmpty { parts.append("Location: \(location)") }
                if let correlationKey, !correlationKey.isEmpty { parts.append("correlation: \(correlationKey)") }
                if bodySnippet != "<empty>" { parts.append("body: \(bodySnippet)") }

                throw AuthenticationError.gsaMalformedResponse(parts.joined(separator: " | "))
            }
        }
        return data
    }

    private static func parsePlistResponse(_ data: Data) throws -> [String: Any] {
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dict = plist as? [String: Any] else {
            throw AuthenticationError.gsaMalformedResponse("invalid plist response")
        }
        return dict
    }

    private static func checkGSAError(_ res: [String: Any]) throws {
        let status: [String: Any]
        if let nested = res["Status"] as? [String: Any] {
            status = nested
        } else {
            status = res
        }

        let ecAny = status["ec"]
        let ec: Int = {
            if let v = ecAny as? Int { return v }
            if let v = ecAny as? Int64 { return Int(v) }
            if let v = ecAny as? NSNumber { return v.intValue }
            return 0
        }()

        if ec != 0 {
            let em = (status["em"] as? String) ?? "unknown error"
            throw AuthenticationError.gsaError(code: ec, message: em)
        }
    }

    // MARK: - Random

    private static func randomBytes(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw AuthenticationError.gsaMalformedResponse("failed to generate random bytes")
        }
        return data
    }
}
