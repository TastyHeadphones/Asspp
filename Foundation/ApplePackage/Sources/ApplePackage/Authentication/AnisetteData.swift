//
//  AnisetteData.swift
//  ApplePackage
//
//  Created by Codex on 2026/2/14.
//

import Foundation

public struct AnisetteData: Sendable {
    public let baseHeaders: [String: String]
    public let generatedAt: Date
    public let serverURL: URL

    public init(baseHeaders: [String: String], generatedAt: Date, serverURL: URL) {
        self.baseHeaders = baseHeaders
        self.generatedAt = generatedAt
        self.serverURL = serverURL
    }
}

public extension AnisetteData {
    var needsRefresh: Bool {
        Date().timeIntervalSince(generatedAt) > 60
    }

    var isValid: Bool {
        Date().timeIntervalSince(generatedAt) < 90
    }

    func headerValue(for name: String) -> String? {
        if let value = baseHeaders[name] {
            return value
        }
        let lower = name.lowercased()
        return baseHeaders.first(where: { $0.key.lowercased() == lower })?.value
    }

    func generateHeaders(
        cpd: Bool,
        clientInfo: Bool,
        appInfo: Bool
    ) throws -> [String: String] {
        guard isValid else {
            throw AuthenticationError.anisetteUnavailable("stale anisette data")
        }

        var headers = baseHeaders

        let oldClientInfo = headers.removeValue(forKey: headers.firstKey(matching: "X-Mme-Client-Info"))
        if clientInfo, let oldClientInfo {
            headers["X-Mme-Client-Info"] = oldClientInfo.normalizedMMeClientInfo
        }

        if appInfo {
            headers["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
            headers["X-Xcode-Version"] = "11.2 (11B41)"
        }

        if cpd {
            headers["bootstrap"] = "true"
            headers["icscrec"] = "true"
            headers["loc"] = "en_GB"
            headers["pbe"] = "false"
            headers["prkgen"] = "true"
            headers["svct"] = "iCloud"
        }

        return headers
    }

    func toPlistDictionary(
        cpd: Bool,
        clientInfo: Bool,
        appInfo: Bool
    ) throws -> [String: Any] {
        let headers = try generateHeaders(cpd: cpd, clientInfo: clientInfo, appInfo: appInfo)
        return headers
    }
}

private extension Dictionary where Key == String, Value == String {
    func firstKey(matching name: String) -> String {
        let lower = name.lowercased()
        return first(where: { $0.key.lowercased() == lower })?.key ?? name
    }
}

private extension String {
    var normalizedMMeClientInfo: String {
        // Expected format:
        // <Device> <OS;Ver;Build> <Bundle/Ver (Build)>
        // We normalize the 3rd <> block to a known AuthKit/Xcode string.
        let replacement = "com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)"

        var ranges: [Range<String.Index>] = []
        var i = startIndex
        while i < endIndex {
            guard let l = self[i...].firstIndex(of: "<") else { break }
            guard let r = self[l...].firstIndex(of: ">") else { break }
            ranges.append(l..<index(after: r))
            i = index(after: r)
        }

        guard ranges.count >= 3 else { return self }

        let third = ranges[2]
        // third includes '<' and '>', replace inside.
        let innerStart = index(after: third.lowerBound)
        let innerEnd = index(before: third.upperBound)
        guard innerStart <= innerEnd else { return self }

        var copy = self
        copy.replaceSubrange(innerStart..<innerEnd, with: replacement)
        return copy
    }
}

