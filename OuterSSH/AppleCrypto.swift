#if OUTERSSH_APPLE_CRYPTO
import CryptoKit
import Foundation
import Security

private enum AppleCryptoError: Error { case invalidKey, unsupportedKey, encryptedKey }

private struct SSHReader {
    let bytes: [UInt8]
    var offset = 0
    mutating func take(_ count: Int) throws -> Data {
        guard count >= 0, count <= bytes.count - offset else { throw AppleCryptoError.invalidKey }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }
    mutating func uint32() throws -> UInt32 {
        try take(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }
    mutating func string() throws -> Data { try take(Int(uint32())) }
}

private func sshString(_ bytes: Data) -> Data {
    var size = UInt32(bytes.count).bigEndian
    var result = withUnsafeBytes(of: &size) { Data($0) }
    result.append(bytes)
    return result
}

private func unsignedInteger(_ bytes: Data) -> Data {
    var result = Data(bytes.drop(while: { $0 == 0 }))
    if result.first.map({ $0 & 0x80 != 0 }) == true { result.insert(0, at: 0) }
    return result
}

private func der(_ tag: UInt8, _ bytes: Data) -> Data {
    var result = Data([tag])
    if bytes.count < 128 { result.append(UInt8(bytes.count)) }
    else {
        var length = bytes.count
        var octets: [UInt8] = []
        while length > 0 { octets.insert(UInt8(length & 255), at: 0); length >>= 8 }
        result.append(0x80 | UInt8(octets.count)); result.append(contentsOf: octets)
    }
    result.append(bytes)
    return result
}

private func derInteger(_ bytes: Data) -> Data {
    let value = unsignedInteger(bytes)
    return der(2, value.isEmpty ? Data([0]) : value)
}

private func derValue(_ reader: inout SSHReader, tag: UInt8) throws -> Data {
    guard try reader.take(1) == Data([tag]) else { throw AppleCryptoError.invalidKey }
    let first = try reader.take(1)[0]
    var length = Int(first)
    if first & 128 != 0 {
        let count = Int(first & 127)
        guard count > 0, count <= 4 else { throw AppleCryptoError.invalidKey }
        length = try reader.take(count).reduce(0) { ($0 << 8) | Int($1) }
    }
    return try reader.take(length)
}

private func rsaInteger(_ reader: inout SSHReader) throws -> Data {
    let encoded = try reader.string()
    guard let first = encoded.first, first & 0x80 == 0,
          encoded.count <= 2049 else { throw AppleCryptoError.invalidKey }
    if first == 0 {
        guard encoded.count > 1, encoded[encoded.startIndex + 1] & 0x80 != 0 else {
            throw AppleCryptoError.invalidKey
        }
    }
    return Data(encoded.drop(while: { $0 == 0 }))
}

private func rsaCRTExponent(_ exponent: Data, prime: Data) throws -> Data {
    guard !prime.isEmpty, prime.last.map({ $0 & 1 == 1 }) == true,
          prime.count > 1 || prime[prime.startIndex] > 2 else {
        throw AppleCryptoError.invalidKey
    }
    var modulus = [UInt8(0)] + prime
    modulus[modulus.count - 1] -= 1
    var remainder = [UInt8](repeating: 0, count: modulus.count)
    var difference = remainder
    defer {
        modulus.withUnsafeMutableBytes { if let base = $0.baseAddress { memset_s(base, $0.count, 0, $0.count) } }
        remainder.withUnsafeMutableBytes { if let base = $0.baseAddress { memset_s(base, $0.count, 0, $0.count) } }
        difference.withUnsafeMutableBytes { if let base = $0.baseAddress { memset_s(base, $0.count, 0, $0.count) } }
    }
    for byte in exponent {
        for bit in (0..<8).reversed() {
            var carry = (byte >> bit) & 1
            for index in remainder.indices.reversed() {
                let next = remainder[index] >> 7
                remainder[index] = (remainder[index] << 1) | carry
                carry = next
            }
            var borrow: UInt16 = 0
            for index in remainder.indices.reversed() {
                let value = UInt16(remainder[index]) &- UInt16(modulus[index]) &- borrow
                difference[index] = UInt8(truncatingIfNeeded: value)
                borrow = value >> 15
            }
            let mask = UInt8(truncatingIfNeeded: borrow &- 1)
            for index in remainder.indices {
                remainder[index] = (difference[index] & mask) | (remainder[index] & ~mask)
            }
        }
    }
    return Data(remainder.drop(while: { $0 == 0 }))
}

private func rsaPrivateKey(_ reader: inout SSHReader) throws -> AppleKey {
    let modulus = try rsaInteger(&reader)
    let publicExponent = try rsaInteger(&reader)
    let privateExponent = try rsaInteger(&reader)
    let coefficient = try rsaInteger(&reader)
    let primeP = try rsaInteger(&reader)
    let primeQ = try rsaInteger(&reader)
    guard primeP.count <= modulus.count, primeQ.count <= modulus.count,
          privateExponent.count <= modulus.count, publicExponent.count <= modulus.count,
          coefficient.count <= primeP.count else { throw AppleCryptoError.invalidKey }
    let exponentP = try rsaCRTExponent(privateExponent, prime: primeP)
    let exponentQ = try rsaCRTExponent(privateExponent, prime: primeQ)
    let fields = [Data([0]), modulus, publicExponent, privateExponent,
                  primeP, primeQ, exponentP, exponentQ, coefficient]
    let encoded = der(0x30, fields.reduce(into: Data()) { $0.append(derInteger($1)) })
    return try AppleKey(kind: 0, bytes: encoded, isPrivate: true)
}

private final class AppleKey {
    let kind: Int32
    let bytes: Data
    let isPrivate: Bool
    let rsa: SecKey?

    init(kind: Int32, bytes: Data, isPrivate: Bool) throws {
        self.kind = kind
        self.bytes = bytes
        self.isPrivate = isPrivate
        if kind == 0 {
            let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: isPrivate ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic]
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(bytes as CFData, attributes as CFDictionary, &error) else {
                throw error?.takeRetainedValue() as Error? ?? AppleCryptoError.invalidKey
            }
            rsa = key
        } else { rsa = nil }
        _ = try publicBytes()
    }

    func publicBytes() throws -> Data {
        switch kind {
        case 0:
            guard let rsa, let key = isPrivate ? SecKeyCopyPublicKey(rsa) : rsa,
                  let data = SecKeyCopyExternalRepresentation(key, nil) else { throw AppleCryptoError.invalidKey }
            return data as Data
        case 1:
            if isPrivate { return try Curve25519.Signing.PrivateKey(rawRepresentation: bytes).publicKey.rawRepresentation }
            return try Curve25519.Signing.PublicKey(rawRepresentation: bytes).rawRepresentation
        case 256:
            if isPrivate { return try P256.Signing.PrivateKey(rawRepresentation: bytes).publicKey.x963Representation }
            return try P256.Signing.PublicKey(x963Representation: bytes).x963Representation
        case 384:
            if isPrivate { return try P384.Signing.PrivateKey(rawRepresentation: bytes).publicKey.x963Representation }
            return try P384.Signing.PublicKey(x963Representation: bytes).x963Representation
        case 521:
            if isPrivate { return try P521.Signing.PrivateKey(rawRepresentation: bytes).publicKey.x963Representation }
            return try P521.Signing.PublicKey(x963Representation: bytes).x963Representation
        default: throw AppleCryptoError.unsupportedKey
        }
    }

    var method: String { kind == 0 ? "ssh-rsa" : kind == 1 ? "ssh-ed25519" : "ecdsa-sha2-nistp\(kind)" }

    func publicBlob() throws -> Data {
        var result = sshString(Data(method.utf8))
        let publicKey = try publicBytes()
        if kind == 0 {
            var outer = SSHReader(bytes: Array(publicKey))
            var sequence = SSHReader(bytes: Array(try derValue(&outer, tag: 0x30)))
            let modulus = try derValue(&sequence, tag: 2)
            let exponent = try derValue(&sequence, tag: 2)
            result.append(sshString(unsignedInteger(exponent)))
            result.append(sshString(unsignedInteger(modulus)))
        } else {
            if kind != 1 { result.append(sshString(Data("nistp\(kind)".utf8))) }
            result.append(sshString(publicKey))
        }
        return result
    }

    func sign(_ digest: Data) throws -> Data {
        guard isPrivate else { throw AppleCryptoError.invalidKey }
        switch kind {
        case 0:
            guard let rsa else { throw AppleCryptoError.invalidKey }
            let algorithm: SecKeyAlgorithm = digest.count == 32 ? .rsaSignatureDigestPKCS1v15SHA256 : .rsaSignatureDigestPKCS1v15SHA512
            guard let signature = SecKeyCreateSignature(rsa, algorithm, digest as CFData, nil) else { throw AppleCryptoError.invalidKey }
            return signature as Data
        case 1: return try Curve25519.Signing.PrivateKey(rawRepresentation: bytes).signature(for: digest)
        default:
            let keyData = try publicBytes() + bytes
            let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
            guard let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil),
                  let signature = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962, digest as CFData, nil) else { throw AppleCryptoError.invalidKey }
            var outer = SSHReader(bytes: Array(signature as Data))
            var sequence = SSHReader(bytes: Array(try derValue(&outer, tag: 0x30)))
            let r = try derValue(&sequence, tag: 2)
            let s = try derValue(&sequence, tag: 2)
            return sshString(unsignedInteger(r)) + sshString(unsignedInteger(s))
        }
    }

    func verify(signature: Data, message: Data, hashLength: Int) throws -> Bool {
        switch kind {
        case 0:
            guard let rsa, let key = isPrivate ? SecKeyCopyPublicKey(rsa) : rsa else { throw AppleCryptoError.invalidKey }
            let algorithm: SecKeyAlgorithm = hashLength == 32 ? .rsaSignatureMessagePKCS1v15SHA256 : .rsaSignatureMessagePKCS1v15SHA512
            return SecKeyVerifySignature(key, algorithm, message as CFData, signature as CFData, nil)
        case 1: return try Curve25519.Signing.PublicKey(rawRepresentation: publicBytes()).isValidSignature(signature, for: message)
        case 256:
            let key = try P256.Signing.PublicKey(x963Representation: publicBytes())
            return try key.isValidSignature(P256.Signing.ECDSASignature(derRepresentation: signature), for: message)
        case 384:
            let key = try P384.Signing.PublicKey(x963Representation: publicBytes())
            return try key.isValidSignature(P384.Signing.ECDSASignature(derRepresentation: signature), for: message)
        case 521:
            let key = try P521.Signing.PublicKey(x963Representation: publicBytes())
            return try key.isValidSignature(P521.Signing.ECDSASignature(derRepresentation: signature), for: message)
        default: throw AppleCryptoError.unsupportedKey
        }
    }
}

private func parsePrivateKey(_ data: Data) throws -> AppleKey {
    guard let text = String(data: data, encoding: .utf8) else { throw AppleCryptoError.invalidKey }
    if text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        let lines = text.split(whereSeparator: \.isNewline)
        guard lines.first == "-----BEGIN OPENSSH PRIVATE KEY-----", lines.last == "-----END OPENSSH PRIVATE KEY-----",
              let decoded = Data(base64Encoded: lines.dropFirst().dropLast().joined()) else { throw AppleCryptoError.invalidKey }
        var reader = SSHReader(bytes: Array(decoded))
        guard try reader.take(15) == Data("openssh-key-v1\0".utf8) else { throw AppleCryptoError.invalidKey }
        let cipher = try reader.string(), kdf = try reader.string(), options = try reader.string()
        guard cipher == Data("none".utf8), kdf == Data("none".utf8) else { throw AppleCryptoError.encryptedKey }
        guard options.isEmpty, try reader.uint32() == 1 else { throw AppleCryptoError.invalidKey }
        let publicBlob = try reader.string()
        let privateBlob = try reader.string()
        guard reader.offset == reader.bytes.count, privateBlob.count % 8 == 0 else { throw AppleCryptoError.invalidKey }
        var inner = SSHReader(bytes: Array(privateBlob))
        let check = try inner.uint32()
        guard try inner.uint32() == check else { throw AppleCryptoError.invalidKey }
        let method = try inner.string()
        let key: AppleKey
        if method == Data("ssh-rsa".utf8) {
            key = try rsaPrivateKey(&inner)
        } else if method == Data("ssh-ed25519".utf8) {
            let publicKey = try inner.string(), secret = try inner.string()
            guard secret.count == 64, publicKey.count == 32, secret.suffix(32) == publicKey else { throw AppleCryptoError.invalidKey }
            key = try AppleKey(kind: 1, bytes: Data(secret.prefix(32)), isPrivate: true)
        } else if let name = String(data: method, encoding: .utf8), name.hasPrefix("ecdsa-sha2-nistp"),
                  let kind = Int32(name.dropFirst("ecdsa-sha2-nistp".count)), [256, 384, 521].contains(kind) {
            guard try inner.string() == Data("nistp\(kind)".utf8) else { throw AppleCryptoError.invalidKey }
            let publicKey = try inner.string()
            let integer = try inner.string()
            guard integer.first.map({ $0 & 128 == 0 }) == true else { throw AppleCryptoError.invalidKey }
            let secret = Data(integer.drop(while: { $0 == 0 }))
            let length = (Int(kind) + 7) / 8
            guard secret.count <= length else { throw AppleCryptoError.invalidKey }
            key = try AppleKey(kind: kind, bytes: Data(repeating: 0, count: length - secret.count) + secret, isPrivate: true)
            guard try key.publicBytes() == publicKey else { throw AppleCryptoError.invalidKey }
        } else { throw AppleCryptoError.unsupportedKey }
        _ = try inner.string()
        let padding = try inner.take(inner.bytes.count - inner.offset)
        guard padding.count <= 8,
              padding.enumerated().allSatisfy({ $0.element == UInt8($0.offset + 1) }),
              try key.publicBlob() == publicBlob else { throw AppleCryptoError.invalidKey }
        return key
    }
    if text.contains("ENCRYPTED") { throw AppleCryptoError.encryptedKey }
    if text.hasPrefix("-----BEGIN RSA PRIVATE KEY-----") {
        let lines = text.split(whereSeparator: \.isNewline)
        guard lines.last == "-----END RSA PRIVATE KEY-----",
              let bytes = Data(base64Encoded: lines.dropFirst().dropLast().joined()) else { throw AppleCryptoError.invalidKey }
        return try AppleKey(kind: 0, bytes: bytes, isPrivate: true)
    }
    if let key = try? P256.Signing.PrivateKey(pemRepresentation: text) {
        return try AppleKey(kind: 256, bytes: key.rawRepresentation, isPrivate: true)
    }
    if let key = try? P384.Signing.PrivateKey(pemRepresentation: text) {
        return try AppleKey(kind: 384, bytes: key.rawRepresentation, isPrivate: true)
    }
    if let key = try? P521.Signing.PrivateKey(pemRepresentation: text) {
        return try AppleKey(kind: 521, bytes: key.rawRepresentation, isPrivate: true)
    }
    throw AppleCryptoError.unsupportedKey
}

private func borrowedData(_ pointer: UnsafeRawPointer, _ count: Int) -> Data { Data(bytes: pointer, count: count) }
private func keyObject(_ pointer: UnsafeMutableRawPointer) -> AppleKey { Unmanaged<AppleKey>.fromOpaque(pointer).takeUnretainedValue() }

@_cdecl("olibssh_apple_key_free")
func releaseAppleKey(_ pointer: UnsafeMutableRawPointer?) {
    if let pointer { Unmanaged<AppleKey>.fromOpaque(pointer).release() }
}

@_cdecl("olibssh_apple_key_create")
func createAppleKey(_ kind: Int32, _ bytes: UnsafeRawPointer, _ count: Int, _ isPrivate: Int32) -> UnsafeMutableRawPointer? {
    guard let key = try? AppleKey(kind: kind, bytes: borrowedData(bytes, count), isPrivate: isPrivate != 0) else { return nil }
    return Unmanaged.passRetained(key).toOpaque()
}

@_cdecl("olibssh_apple_key_parse")
func parseAppleKey(_ bytes: UnsafeRawPointer, _ count: Int, _ errorCode: UnsafeMutablePointer<Int32>) -> UnsafeMutableRawPointer? {
    do { return Unmanaged.passRetained(try parsePrivateKey(borrowedData(bytes, count))).toOpaque() }
    catch AppleCryptoError.encryptedKey { errorCode.pointee = 1 }
    catch AppleCryptoError.unsupportedKey { errorCode.pointee = 2 }
    catch { errorCode.pointee = 3 }
    return nil
}

@_cdecl("olibssh_apple_key_kind")
func appleKeyKind(_ pointer: UnsafeMutableRawPointer) -> Int32 { keyObject(pointer).kind }

@_cdecl("olibssh_apple_key_export")
func exportAppleKey(_ pointer: UnsafeMutableRawPointer, _ output: UnsafeMutableRawPointer?, _ capacity: Int) -> Int {
    guard let data = try? keyObject(pointer).publicBlob() else { return -1 }
    if let output { guard capacity >= data.count else { return -1 }; data.copyBytes(to: output.assumingMemoryBound(to: UInt8.self), count: data.count) }
    return data.count
}

@_cdecl("olibssh_apple_sign")
func signAppleKey(_ pointer: UnsafeMutableRawPointer, _ bytes: UnsafeRawPointer, _ count: Int, _ output: UnsafeMutableRawPointer, _ capacity: Int) -> Int {
    guard let signature = try? keyObject(pointer).sign(borrowedData(bytes, count)), signature.count <= capacity else { return -1 }
    signature.copyBytes(to: output.assumingMemoryBound(to: UInt8.self), count: signature.count)
    return signature.count
}

@_cdecl("olibssh_apple_verify")
func verifyAppleKey(_ pointer: UnsafeMutableRawPointer, _ signature: UnsafeRawPointer, _ signatureCount: Int,
                    _ message: UnsafeRawPointer, _ messageCount: Int, _ hashLength: Int) -> Int32 {
    do { return try keyObject(pointer).verify(signature: borrowedData(signature, signatureCount), message: borrowedData(message, messageCount), hashLength: hashLength) ? 0 : -1 }
    catch { return -1 }
}

@_cdecl("olibssh_apple_ec_generate")
func generateAppleEC(_ kind: Int32, _ privateBytes: UnsafeMutableRawPointer, _ publicBytes: UnsafeMutableRawPointer) -> Int32 {
    let secret: Data, publicKey: Data
    switch kind {
    case 1:
        let key = Curve25519.KeyAgreement.PrivateKey()
        secret = key.rawRepresentation; publicKey = key.publicKey.rawRepresentation
    case 256:
        let key = P256.KeyAgreement.PrivateKey()
        secret = key.rawRepresentation; publicKey = key.publicKey.x963Representation
    case 384:
        let key = P384.KeyAgreement.PrivateKey()
        secret = key.rawRepresentation; publicKey = key.publicKey.x963Representation
    case 521:
        let key = P521.KeyAgreement.PrivateKey()
        secret = key.rawRepresentation; publicKey = key.publicKey.x963Representation
    default: return -1
    }
    secret.copyBytes(to: privateBytes.assumingMemoryBound(to: UInt8.self), count: secret.count)
    publicKey.copyBytes(to: publicBytes.assumingMemoryBound(to: UInt8.self), count: publicKey.count)
    return Int32(publicKey.count)
}

@_cdecl("olibssh_apple_ec_shared")
func sharedAppleEC(_ kind: Int32, _ privateBytes: UnsafeRawPointer, _ privateCount: Int,
                   _ publicBytes: UnsafeRawPointer, _ publicCount: Int, _ output: UnsafeMutableRawPointer) -> Int32 {
    do {
        let secret: SharedSecret
        let bytes = borrowedData(privateBytes, privateCount), peer = borrowedData(publicBytes, publicCount)
        switch kind {
        case 1: secret = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes).sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: peer))
        case 256: secret = try P256.KeyAgreement.PrivateKey(rawRepresentation: bytes).sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: peer))
        case 384: secret = try P384.KeyAgreement.PrivateKey(rawRepresentation: bytes).sharedSecretFromKeyAgreement(with: P384.KeyAgreement.PublicKey(x963Representation: peer))
        case 521: secret = try P521.KeyAgreement.PrivateKey(rawRepresentation: bytes).sharedSecretFromKeyAgreement(with: P521.KeyAgreement.PublicKey(x963Representation: peer))
        default: return -1
        }
        return secret.withUnsafeBytes { bytes in
            guard bytes.contains(where: { $0 != 0 }) else { return -1 }
            guard let baseAddress = bytes.baseAddress else { return -1 }
            output.copyMemory(from: baseAddress, byteCount: bytes.count)
            return Int32(bytes.count)
        }
    } catch { return -1 }
}

private final class ApplePacketKey {
    let key: SymmetricKey
    init(_ bytes: UnsafeRawPointer, _ count: Int) { key = SymmetricKey(data: UnsafeRawBufferPointer(start: bytes, count: count)) }
}

@_cdecl("olibssh_apple_packet_key_create")
func createApplePacketKey(_ bytes: UnsafeRawPointer, _ count: Int) -> UnsafeMutableRawPointer {
    Unmanaged.passRetained(ApplePacketKey(bytes, count)).toOpaque()
}

@_cdecl("olibssh_apple_packet_key_free")
func releaseApplePacketKey(_ pointer: UnsafeMutableRawPointer) { Unmanaged<ApplePacketKey>.fromOpaque(pointer).release() }

@_cdecl("olibssh_apple_gcm")
func appleGCM(_ pointer: UnsafeMutableRawPointer, _ iv: UnsafeRawPointer, _ packet: UnsafeMutableRawPointer,
              _ count: Int, _ encrypt: Int32) -> Int32 {
    do {
        let key = Unmanaged<ApplePacketKey>.fromOpaque(pointer).takeUnretainedValue().key
        let nonce = try AES.GCM.Nonce(data: UnsafeRawBufferPointer(start: iv, count: 12))
        let aad = UnsafeRawBufferPointer(start: packet, count: 4)
        let payload = UnsafeRawBufferPointer(start: packet + 4, count: count)
        if encrypt != 0 {
            let box = try AES.GCM.seal(payload, using: key, nonce: nonce, authenticating: aad)
            box.ciphertext.copyBytes(to: (packet + 4).assumingMemoryBound(to: UInt8.self), count: count)
            box.tag.copyBytes(to: (packet + 4 + count).assumingMemoryBound(to: UInt8.self), count: 16)
        } else {
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: payload, tag: UnsafeRawBufferPointer(start: packet + 4 + count, count: 16))
            let plaintext = try AES.GCM.open(box, using: key, authenticating: aad)
            plaintext.copyBytes(to: (packet + 4).assumingMemoryBound(to: UInt8.self), count: count)
        }
        return 0
    } catch { return -1 }
}
@_cdecl("olibssh_apple_rsa_public")
func appleRSAPublic(_ exponent: UnsafeRawPointer, _ exponentCount: Int, _ modulus: UnsafeRawPointer, _ modulusCount: Int) -> UnsafeMutableRawPointer? {
    let bytes = der(0x30, derInteger(borrowedData(modulus, modulusCount)) + derInteger(borrowedData(exponent, exponentCount)))
    guard let key = try? AppleKey(kind: 0, bytes: bytes, isPrivate: false) else { return nil }
    return Unmanaged.passRetained(key).toOpaque()
}

@_cdecl("olibssh_apple_verify_ec")
func appleVerifyEC(_ key: UnsafeMutableRawPointer, _ r: UnsafeRawPointer, _ rCount: Int, _ s: UnsafeRawPointer, _ sCount: Int,
                   _ message: UnsafeRawPointer, _ count: Int) -> Int32 {
    let signature = der(0x30, derInteger(borrowedData(r, rCount)) + derInteger(borrowedData(s, sCount)))
    do { return try keyObject(key).verify(signature: signature, message: borrowedData(message, count), hashLength: 0) ? 0 : -1 }
    catch { return -1 }
}
#endif
