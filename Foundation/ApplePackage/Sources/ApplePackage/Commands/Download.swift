//
//  Download.swift
//  ApplePackage
//
//  Created by qaq on 9/15/25.
//

import AsyncHTTPClient
import Foundation

public enum Download {
    public nonisolated static func download(
        account: inout Account,
        app: Software,
        externalVersionID: String? = nil
    ) async throws -> DownloadOutput {
        let deviceIdentifier = Configuration.deviceIdentifier

        let client = HTTPClient(
            eventLoopGroupProvider: .singleton,
            configuration: .init(
                tlsConfiguration: Configuration.tlsConfiguration,
                redirectConfiguration: .disallow,
                timeout: .init(
                    connect: .seconds(Configuration.timeoutConnect),
                    read: .seconds(Configuration.timeoutRead)
                )
            ).then { $0.httpVersion = .http1Only }
        )
        defer { _ = client.shutdown() }

        let anisetteHeaders = try await Configuration.anisetteHeaders()
        let request = try makeRequest(
            account: account,
            app: app,
            guid: deviceIdentifier,
            externalVersionID: externalVersionID ?? "",
            anisetteHeaders: anisetteHeaders
        )
        let response = try await client.execute(request: request).get()

        account.cookie.mergeCookies(response.cookies)

        try ensure(response.status == .ok, "download request failed with status \(response.status.code)")

        guard var body = response.body,
              let data = body.readData(length: body.readableBytes)
        else {
            try ensureFailed("response body is empty")
        }

        let plist = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        ) as? [String: Any]
        guard let dict = plist else { try ensureFailed("invalid response") }

        if let failureType = dict["failureType"] as? String {
            if failureType.isEmpty,
               let customerMessage = dict["customerMessage"] as? String,
               customerMessage == "MZFinance.BadLogin.Configurator_message"
            {
                throw AuthenticationError.twoFactorRequired("""
                Apple ID authentication requires verification code.
                Re-authenticate the account with a 2FA code, then retry.
                """)
            }
            switch failureType {
            case "2034":
                try ensureFailed("password token is expired")
            case "9610":
                throw ApplePackageError.licenseRequired
            default:
                if let customerMessage = dict["customerMessage"] as? String {
                    try ensureFailed(customerMessage)
                }
                try ensureFailed("download failed: \(failureType)")
            }
        }

        guard let items = dict["songList"] as? [[String: Any]], !items.isEmpty else {
            try ensureFailed("no items in response")
        }

        let item = items[0]
        guard let url = item["URL"] as? String else {
            try ensureFailed("missing download URL")
        }

        guard let metadata = item["metadata"] as? [String: Any] else {
            try ensureFailed("missing metadata")
        }

        let version = (metadata["bundleShortVersionString"] as? String)
        let bundleVersion = metadata["bundleVersion"] as? String

        guard let version, let bundleVersion else {
            try ensureFailed("missing required information")
        }

        var sinfs: [Sinf] = []
        if let sinfData = item["sinfs"] as? [[String: Any]] {
            for sinfItem in sinfData {
                if let id = sinfItem["id"] as? Int64,
                   let data = sinfItem["sinf"] as? Data
                {
                    sinfs.append(Sinf(id: id, sinf: data))
                } else {
                    try ensureFailed("invalid sinf item")
                }
            }
        }
        try ensure(!sinfs.isEmpty, "no sinf found in response")

        return DownloadOutput(
            downloadURL: url,
            sinfs: sinfs,
            bundleShortVersionString: version,
            bundleVersion: bundleVersion
        )
    }

    private nonisolated static func makeRequest(
        account: Account,
        app: Software,
        guid: String,
        externalVersionID: String,
        anisetteHeaders: [String: String]
    ) throws -> HTTPClient.Request {
        var payload: [String: Any] = [
            "creditDisplay": "",
            "guid": guid,
            "salableAdamId": app.id,
        ]

        if !externalVersionID.isEmpty {
            payload["externalVersionId"] = externalVersionID
        }

        let data = try PropertyListSerialization.data(fromPropertyList: payload, format: .xml, options: 0)

        var headers: [(String, String)] = [
            ("Content-Type", "application/x-apple-plist"),
            ("User-Agent", Configuration.userAgent),
            ("iCloud-DSID", account.directoryServicesIdentifier),
            ("X-Dsid", account.directoryServicesIdentifier),
            ("X-Apple-Store-Front", "\(account.store)-1"),
            ("X-Token", account.passwordToken),
        ]

        let url = URL(string: "https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct")!
        for (k, v) in anisetteHeaders {
            if headers.contains(where: { $0.0.lowercased() == k.lowercased() }) {
                continue
            }
            headers.append((k, v))
        }

        for item in account.cookie.buildCookieHeader(url) {
            headers.append(item)
        }

        return try .init(
            url: url.absoluteString,
            method: .POST,
            headers: .init(headers),
            body: .data(data)
        )
    }
}
