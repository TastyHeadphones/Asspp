//
//  AnisetteDataProvider.swift
//  ApplePackage
//
//  Created by Codex on 2026/2/14.
//

import Foundation

public protocol AnisetteDataProviding: Sendable {
    func anisetteData() async throws -> AnisetteData
}

public actor RemoteAnisetteDataProvider: AnisetteDataProviding {
    private let serverURL: URL
    private var cached: AnisetteData?

    public init(serverURL: URL) {
        self.serverURL = serverURL
    }

    public func anisetteData() async throws -> AnisetteData {
        if let cached, !cached.needsRefresh {
            return cached
        }

        let anisette = try await fetch()
        cached = anisette
        return anisette
    }

    private func fetch() async throws -> AnisetteData {
        var req = URLRequest(url: serverURL)
        req.httpMethod = "GET"
        req.cachePolicy = .reloadIgnoringLocalCacheData
        req.timeoutInterval = 15

        let (data, response) = try await URLSession.shared.data(for: req)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw AuthenticationError.anisetteUnavailable("server returned HTTP \(http.statusCode)")
        }

        let obj = try JSONSerialization.jsonObject(with: data, options: [])
        guard let dict = obj as? [String: Any] else {
            throw AuthenticationError.anisetteUnavailable("unexpected response")
        }

        var headers: [String: String] = [:]
        for (k, v) in dict {
            guard let value = v as? String else { continue }
            headers[k] = value
        }

        guard !headers.isEmpty else {
            throw AuthenticationError.anisetteUnavailable("empty response")
        }

        return AnisetteData(baseHeaders: headers, generatedAt: Date(), serverURL: serverURL)
    }
}

