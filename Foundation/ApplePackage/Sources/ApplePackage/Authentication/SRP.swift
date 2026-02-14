//
//  SRP.swift
//  ApplePackage
//
//  Created by Codex on 2026/2/14.
//

import BigInt
import Foundation

struct SrpGroup: Sendable {
    let n: BigUInt
    let g: BigUInt
}

enum SrpGroups {
    // RFC 5054 2048-bit group (N as big-endian bytes).
    static let rfc5054_2048: SrpGroup = {
        let nBase64 = "rGvbQTJKmpvxZt5eE4lYL69ytmUZh+4H/DGSlD21YFCjcynLtKCZ7YGT4HV3Z6E91SMSq0sDMQ3Nf0ip2gT9UOgIOWntt2ewz2CVF5oWOrNmGgX71fqq6CkYqZYvC5O4Vfl5k+yXXuqoDXQK2/T/dHNZ0EHVwz6nHSgeRGsUdzvKl7Q6I/uAFna9IHpDbGSB8dK5B4cXRhpbnTLmiPh3SFRFI7UksNV9Xqd6J3XS7PoDLPvb9S+zeGFgJ5AE5Xrmr4dOcwPOUymczAQce8MI2CpWmPOo0MOCca41+Onb+7aUtcgD2J965DXeI21SX1R1m2XjcvzWjvIPpxEfnkr/cw=="
        // NOTE: If you change this constant, the SRP group changes and auth will fail.
        let nData = Data(base64Encoded: nBase64) ?? Data()
        precondition(nData.count == 256, "invalid SRP group size")
        return SrpGroup(n: BigUInt(nData), g: BigUInt(2))
    }()
}

struct SrpClientVerifier: Sendable {
    let m1: Data
    let expectedM2: Data
    let key: Data

    func verifyServerProof(_ m2: Data) throws {
        guard m2 == expectedM2 else {
            throw AuthenticationError.gsaMalformedResponse("server proof mismatch")
        }
    }
}

struct SrpClient: Sendable {
    let group: SrpGroup

    init(group: SrpGroup) {
        self.group = group
    }

    func computePublicEphemeral(a: Data) -> Data {
        let aInt = BigUInt(a)
        let aPub = group.g.power(aInt, modulus: group.n)
        return aPub.serialize()
    }

    func processReply(
        a: Data,
        username: Data,
        password: Data,
        salt: Data,
        bPub: Data
    ) throws -> SrpClientVerifier {
        let aInt = BigUInt(a)
        let aPubInt = group.g.power(aInt, modulus: group.n)

        let bPubInt = BigUInt(bPub)

        // Safeguard against malicious B.
        if bPubInt % group.n == 0 {
            throw AuthenticationError.gsaMalformedResponse("illegal server ephemeral")
        }

        let aPubBytes = aPubInt.serialize()
        let bPubBytes = bPubInt.serialize()

        let u = BigUInt(Crypto.sha256(aPubBytes + bPubBytes))
        let k = computeK()
        let identityHash = computeIdentityHash(password: password) // no username in x
        let x = BigUInt(Crypto.sha256(salt + identityHash))

        let sInt = computePremasterSecret(
            bPub: bPubInt,
            k: k,
            x: x,
            a: aInt,
            u: u
        )

        let key = Crypto.sha256(sInt.serialize())

        let m1 = computeM1(
            aPub: aPubBytes,
            bPub: bPubBytes,
            key: key,
            username: username,
            salt: salt
        )

        let m2 = Crypto.sha256(aPubBytes + m1 + key)

        return SrpClientVerifier(m1: m1, expectedM2: m2, key: key)
    }

    private func computeIdentityHash(password: Data) -> Data {
        Crypto.sha256(Data(":".utf8) + password)
    }

    private func computeK() -> BigUInt {
        let nBytes = group.n.serialize()
        let gBytes = group.g.serialize()
        let paddedG = Data(repeating: 0, count: max(0, nBytes.count - gBytes.count)) + gBytes
        return BigUInt(Crypto.sha256(nBytes + paddedG))
    }

    private func computePremasterSecret(
        bPub: BigUInt,
        k: BigUInt,
        x: BigUInt,
        a: BigUInt,
        u: BigUInt
    ) -> BigUInt {
        let n = group.n
        let gx = group.g.power(x, modulus: n)
        let kgx = (k * gx) % n

        // base = (N + B - kg^x) mod N
        let base = (n + bPub - kgx) % n
        let exp = (u * x) + a
        return base.power(exp, modulus: n)
    }

    private func computeM1(
        aPub: Data,
        bPub: Data,
        key: Data,
        username: Data,
        salt: Data
    ) -> Data {
        let nBytes = group.n.serialize()
        let gBytes = group.g.serialize()
        let paddedG = Data(repeating: 0, count: max(0, nBytes.count - gBytes.count)) + gBytes

        let gHash = Crypto.sha256(paddedG)
        let nHash = Crypto.sha256(nBytes)
        let xored = Data(zip(gHash, nHash).map { $0 ^ $1 })

        let userHash = Crypto.sha256(username)

        return Crypto.sha256(xored + userHash + salt + aPub + bPub + key)
    }
}

private func + (lhs: Data, rhs: Data) -> Data {
    var out = lhs
    out.append(rhs)
    return out
}
