//
//  AuthenticationError.swift
//  ApplePackage
//
//  Created by Codex on 2026/2/14.
//

import Foundation

public enum AuthenticationError: Error, LocalizedError, Sendable {
    case legacyForbidden(correlationKey: String?)
    case twoFactorRequired(String)
    case invalidTwoFactorCode
    case gsaError(code: Int, message: String)
    case gsaMalformedResponse(String)
    case anisetteUnavailable(String)

    public var errorDescription: String? {
        switch self {
        case let .legacyForbidden(correlationKey):
            if let correlationKey, !correlationKey.isEmpty {
                return "Legacy authentication returned HTTP 403 (correlation: \(correlationKey))."
            }
            return "Legacy authentication returned HTTP 403."
        case let .twoFactorRequired(message):
            return message
        case .invalidTwoFactorCode:
            return "Invalid verification code."
        case let .gsaError(code, message):
            return "GSA authentication failed (ec=\(code)): \(message)"
        case let .gsaMalformedResponse(message):
            return "GSA authentication failed: \(message)"
        case let .anisetteUnavailable(message):
            return "Anisette unavailable: \(message)"
        }
    }
}

