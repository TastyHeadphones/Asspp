//
//  Crypto.swift
//  ApplePackage
//
//  Created by Codex on 2026/2/14.
//

import CryptoKit
import CryptoSwift
import Foundation

enum Crypto {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func hmacSHA256(key: Data, message: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)
        return Data(mac)
    }

    static func pbkdf2SHA256(
        password: Data,
        salt: Data,
        iterations: Int,
        keyLength: Int
    ) throws -> Data {
        try ensure(iterations > 0, "pbkdf2: invalid iterations")
        try ensure(keyLength > 0, "pbkdf2: invalid key length")

        do {
            let pbkdf2 = try PKCS5.PBKDF2(
                password: Array(password),
                salt: Array(salt),
                iterations: iterations,
                keyLength: keyLength,
                variant: .sha2(.sha256)
            )
            return Data(try pbkdf2.calculate())
        } catch {
            throw AuthenticationError.gsaMalformedResponse("pbkdf2 failed: \(error.localizedDescription)")
        }
    }

    static func aes256CbcDecryptPkcs7(
        _ ciphertext: Data,
        key: Data,
        iv: Data
    ) throws -> Data {
        try ensure(key.count == 32, "aes-cbc: invalid key size")
        try ensure(iv.count == 16, "aes-cbc: invalid iv size")

        do {
            let aes = try AES(
                key: Array(key),
                blockMode: CBC(iv: Array(iv)),
                padding: .pkcs7
            )
            return Data(try aes.decrypt(Array(ciphertext)))
        } catch {
            throw AuthenticationError.gsaMalformedResponse("aes-cbc decrypt failed: \(error.localizedDescription)")
        }
    }
}

extension Data {
    var hexLowercased: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
