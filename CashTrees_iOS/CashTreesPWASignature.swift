//
//  CashTreesPWASignature.swift
//  CashTrees_iOS
//
//  Signed OTA manifest, format v2.
//
//  update.json = {"ver","filename","signed":{"payload":<base64>,"signatures":[{"keyId","sig"}]}}
//  Signed message = "beamio-pwa-ota/v2\n" + payload bytes (Ed25519). The payload is parsed from the exact bytes that
//  were verified; it is never re-serialised. Trust comes only from a signature by a compiled-in public key; the payload's
//  sha256, size and contentDigest are integrity conditions that must all hold as well.
//

import CryptoKit
import Foundation
import ZIPFoundation

nonisolated struct CashTreesPWAOtaPublicKey: Equatable {
    let keyId: String
    let publicKeyBase64: String
}

/// Public keys trusted to sign the OTA manifest. Several may be listed so a key can be rotated (ship old + new, sign with
/// the new one). The production table is empty until production keys exist: an empty table means no OTA at all.
nonisolated enum CashTreesPWAOtaKeys {
    static let production: [CashTreesPWAOtaPublicKey] = []

    /// The table the app uses. Only a build compiled with BEAMIO_QA_OTA can add a key, from its own Info.plist.
    static var trusted: [CashTreesPWAOtaPublicKey] {
        #if BEAMIO_QA_OTA
        if let qa = CashTreesPWAOtaQA.publicKey { return production + [qa] }
        #endif
        return production
    }

    /// First 16 hex of SHA-256 over the sorted key ids joined by "\n". Bound into the completion record.
    static func tableId(_ keys: [CashTreesPWAOtaPublicKey]) -> String {
        let ids = keys.map(\.keyId).sorted().joined(separator: "\n")
        return String(SHA256.hash(data: Data(ids.utf8)).map { String(format: "%02x", $0) }.joined().prefix(16))
    }

    static var currentTableId: String { tableId(trusted) }
}

/// Release phase: enforced. Only bundles whose verdict is `.ok` are ever staged or activated. A compile-time constant: no
/// server flag, setting or QA switch can change it.
nonisolated enum CashTreesPWAOtaPolicy {
    static let enforce = true
    /// SHA-256 (hex) of signed payloads that must never be accepted again. Empty by default.
    static let revokedPayloads: Set<String> = []
}

nonisolated enum CashTreesPWAOtaVerdict: String, Equatable {
    case ok
    case malformed
    case missingSignature = "missing_signature"
    case untrustedKey = "untrusted_key"
    case badSignature = "bad_signature"
    case revoked
    case mismatch
    case downgrade
    case shellTooOld = "shell_too_old"
    case sizeMismatch = "size_mismatch"
    case hashMismatch = "hash_mismatch"
    case noncanonicalZip = "noncanonical_zip"
    case contentMismatch = "content_mismatch"
    /// Shell-side pre-download limit (payload.size above MAX_ZIP_BYTES); not a manifest v2.0 verdict.
    case tooLarge = "too_large"

    /// The network status class written to ota-status.v1.json.
    var statusClass: String {
        switch self {
        case .ok: return "verified-staged"
        case .missingSignature, .malformed, .untrustedKey, .badSignature, .mismatch, .revoked: return "rejected-signature"
        case .sizeMismatch, .hashMismatch, .contentMismatch, .noncanonicalZip, .tooLarge: return "rejected-integrity"
        case .downgrade, .shellTooOld: return "not-applicable"
        }
    }
}

nonisolated struct CashTreesPWAOtaManifest: Equatable {
    let ver: String
    let filename: String
    let sha256: String
    let size: Int64
    let contentDigest: String
    let minShellIos: Int64
    let minShellAndroid: Int64
    let issuedAt: Int64
    let keyId: String
    let payloadSha256: String
}

nonisolated struct CashTreesPWAOtaManifestCheck: Equatable {
    let verdict: CashTreesPWAOtaVerdict
    var manifest: CashTreesPWAOtaManifest? = nil
    /// The signed object to store as ota-signed/<contentDigest>.json (raw signed object plus the outer ver/filename).
    var signedObject: Data? = nil
}

/// Manifest v2.0 (revision 1) verification, in the specification's order (steps 1–9 before download, 10–13 after).
nonisolated struct CashTreesPWAOtaVerifier {
    static let payloadType = "beamio-pwa-ota"
    static let payloadVersion: Int64 = 2
    static let contentAlg = "beamio-tree-v1"
    static let signDomain = "beamio-pwa-ota/v2\n"
    static let maxSignedObjectBytes = 8192
    /// Shell limit on the ZIP file itself, checked before downloading (payload.size).
    static let maxZipBytes: Int64 = 128 * 1024 * 1024
    private static let maxPayloadBytes = 4096
    private static let maxSignatures = 8

    private let trusted: [String: Curve25519.Signing.PublicKey]
    private let shellBuild: Int64
    private let platform: String
    private let revoked: Set<String>

    init(trustedKeys: [CashTreesPWAOtaPublicKey], shellBuild: Int64, platform: String = "ios",
         revoked: Set<String> = CashTreesPWAOtaPolicy.revokedPayloads) {
        var map: [String: Curve25519.Signing.PublicKey] = [:]
        for key in trustedKeys {
            guard let raw = Data(base64Encoded: key.publicKeyBase64), raw.count == 32,
                  let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: raw),
                  Self.keyId(of: raw) == key.keyId
            else { continue }
            map[key.keyId] = pub
        }
        trusted = map
        self.shellBuild = shellBuild
        self.platform = platform
        self.revoked = revoked
    }

    static func keyId(of rawPublicKey: Data) -> String {
        String(SHA256.hash(data: rawPublicKey).map { String(format: "%02x", $0) }.joined().prefix(16))
    }

    /// `CFBundleVersion` of the running app (0 when missing).
    static var currentShellBuild: Int64 {
        Int64(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "") ?? 0
    }

    /// Steps 1–9 on update.json. `referenceVersion` is the selected verified bundle (or the embedded constant).
    func verifyManifest(_ updateJson: Data, referenceVersion: String?) -> CashTreesPWAOtaManifestCheck {
        guard let doc = (try? JSONSerialization.jsonObject(with: updateJson)) as? [String: Any] else {
            return .init(verdict: .malformed)
        }
        guard let signedValue = doc["signed"], !(signedValue is NSNull) else { return .init(verdict: .missingSignature) }
        guard let signed = signedValue as? [String: Any] else { return .init(verdict: .malformed) }
        var object = signed
        object["updateVer"] = doc["ver"] ?? NSNull()
        object["updateFilename"] = doc["filename"] ?? NSNull()
        guard let objectData = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
              objectData.count <= Self.maxSignedObjectBytes
        else { return .init(verdict: .malformed) }
        var check = verify(signed: signed, outerVer: doc["ver"], outerFilename: doc["filename"], referenceVersion: referenceVersion,
                           checkReference: true)
        if check.verdict == .ok { check.signedObject = objectData }
        return check
    }

    /// Re-verifies a stored signed object (ota-signed/<digest>.json): the same steps without the version order check.
    func verifySignedObject(_ data: Data) -> CashTreesPWAOtaManifestCheck {
        guard data.count <= Self.maxSignedObjectBytes,
              let signed = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return .init(verdict: .malformed) }
        return verify(signed: signed, outerVer: signed["updateVer"], outerFilename: signed["updateFilename"],
                      referenceVersion: nil, checkReference: false)
    }

    private func verify(signed: [String: Any], outerVer: Any?, outerFilename: Any?, referenceVersion: String?,
                        checkReference: Bool) -> CashTreesPWAOtaManifestCheck {
        // 1–2. Structure and missing signature, in the reference order: a "signatures" value that is absent or not an
        // array is malformed; an empty array is missing_signature; then the payload, then each item's shape (an object
        // with a 16-hex keyId and a string sig). An item whose sig is not strict base64 of 64 bytes is skipped below,
        // not a malformed document.
        guard let signatures = signed["signatures"] as? [Any] else { return .init(verdict: .malformed) }
        if signatures.isEmpty { return .init(verdict: .missingSignature) }
        if signatures.count > Self.maxSignatures { return .init(verdict: .malformed) }
        guard let payloadB64 = signed["payload"] as? String, let payload = Self.strictBase64(payloadB64),
              payload.count <= Self.maxPayloadBytes
        else { return .init(verdict: .malformed) }
        var items: [(keyId: String, sigB64: String)] = []
        for item in signatures {
            guard let entry = item as? [String: Any],
                  let id = entry["keyId"] as? String, Self.matches(Self.hex16, id),
                  let sigB64 = entry["sig"] as? String
            else { return .init(verdict: .malformed) }
            items.append((id, sigB64))
        }
        // 3–4. Trusted key and a signature over exactly these payload bytes.
        let message = Data(Self.signDomain.utf8) + payload
        var keyId: String?
        var sawTrusted = false
        for item in items {
            guard let key = trusted[item.keyId] else { continue }
            sawTrusted = true
            guard let sig = Self.strictBase64(item.sigB64), sig.count == 64 else { continue }
            if key.isValidSignature(sig, for: message) {
                keyId = item.keyId
                break
            }
        }
        guard let keyId else { return .init(verdict: sawTrusted ? .badSignature : .untrustedKey) }
        // 5. Payload v2, canonical bytes.
        let payloadHash = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        guard let manifest = Self.parsePayload(payload, keyId: keyId, payloadSha256: payloadHash) else {
            return .init(verdict: .malformed)
        }
        // 6. Revocation.
        if revoked.contains(payloadHash) { return .init(verdict: .revoked, manifest: manifest) }
        // 7. Outer ver/filename.
        if outerVer as? String != manifest.ver || outerFilename as? String != manifest.filename {
            return .init(verdict: .mismatch, manifest: manifest)
        }
        // 8. Only strictly newer than the verified reference.
        if checkReference, let referenceVersion,
           CashTreesPWAVersion.isStrictlyNewer(old: referenceVersion, new: manifest.ver) != true {
            return .init(verdict: .downgrade, manifest: manifest)
        }
        // 9. Minimum shell.
        let minShell = platform == "android" ? manifest.minShellAndroid : manifest.minShellIos
        if shellBuild < minShell { return .init(verdict: .shellTooOld, manifest: manifest) }
        return .init(verdict: .ok, manifest: manifest)
    }

    /// Steps 10–11 on the downloaded ZIP bytes, before anything is unpacked.
    func verifyBundle(_ manifest: CashTreesPWAOtaManifest, zip: URL) -> CashTreesPWAOtaVerdict {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: zip.path),
              let size = (attrs[.size] as? NSNumber)?.int64Value,
              size == manifest.size
        else { return .sizeMismatch }
        return CashTreesPWASameVersionRule.fileSHA256(at: zip) == manifest.sha256 ? .ok : .hashMismatch
    }

    /// Steps 10–13: bytes, structure (§5), bounded extraction into `workDir`, inner ver and beamio-tree-v1.
    func verifyBundleFull(_ manifest: CashTreesPWAOtaManifest, zip: URL, workDir: URL) -> CashTreesPWAOtaVerdict {
        let bytes = verifyBundle(manifest, zip: zip)
        guard bytes == .ok else { return bytes }
        return CashTreesPWAZipCanonical.extractVerified(zip: zip, to: workDir, expectedVer: manifest.ver,
                                                        expectedContentDigest: manifest.contentDigest)
    }

    // MARK: - Payload

    private static let filenamePattern = try! NSRegularExpression(pattern: #"^[A-Za-z0-9._-]{1,128}\.zip$"#)
    private static let hex64 = try! NSRegularExpression(pattern: #"^[0-9a-f]{64}$"#)
    private static let hex16 = try! NSRegularExpression(pattern: #"^[0-9a-f]{16}$"#)
    private static let base64Pattern = try! NSRegularExpression(pattern: #"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"#)

    private static func matches(_ re: NSRegularExpression, _ s: String) -> Bool {
        re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    /// Standard base64 (RFC 4648 alphabet, padded, no whitespace) only.
    private static func strictBase64(_ s: String) -> Data? {
        guard matches(base64Pattern, s) else { return nil }
        return Data(base64Encoded: s)
    }

    /// A JSON integer only (no float, no bool, no string), non-negative and safe.
    private static func strictInt(_ value: Any?) -> Int64? {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
        let d = n.doubleValue
        guard d == d.rounded(), d >= 0, d <= 9_007_199_254_740_991 else { return nil }
        return n.int64Value
    }

    /// Parses payload v2 and requires the exact canonical serialization (field order fixed, no whitespace, decimal
    /// integers, ASCII strings without escapes) to equal the verified bytes (M1).
    private static func parsePayload(_ payload: Data, keyId: String, payloadSha256: String) -> CashTreesPWAOtaManifest? {
        guard let p = (try? JSONSerialization.jsonObject(with: payload)) as? [String: Any],
              Set(p.keys) == ["type", "v", "ver", "filename", "sha256", "size", "contentAlg", "contentDigest", "minShell", "issuedAt"],
              p["type"] as? String == payloadType,
              strictInt(p["v"]) == payloadVersion,
              let ver = p["ver"] as? String, CashTreesPWAVersion.parse(ver) != nil,
              let filename = p["filename"] as? String, matches(filenamePattern, filename),
              let sha256 = p["sha256"] as? String, matches(hex64, sha256),
              let size = strictInt(p["size"]), size > 0,
              p["contentAlg"] as? String == contentAlg,
              let contentDigest = p["contentDigest"] as? String, matches(hex64, contentDigest),
              let minShell = p["minShell"] as? [String: Any], Set(minShell.keys) == ["ios", "android"],
              let minIos = strictInt(minShell["ios"]),
              let minAndroid = strictInt(minShell["android"]),
              let issuedAt = strictInt(p["issuedAt"])
        else { return nil }
        let canonical = #"{"type":"\#(payloadType)","v":2,"ver":"\#(ver)","filename":"\#(filename)","sha256":"\#(sha256)","size":\#(size),"contentAlg":"\#(contentAlg)","contentDigest":"\#(contentDigest)","minShell":{"ios":\#(minIos),"android":\#(minAndroid)},"issuedAt":\#(issuedAt)}"#
        guard Data(canonical.utf8) == payload else { return nil }
        return CashTreesPWAOtaManifest(
            ver: ver, filename: filename, sha256: sha256, size: size, contentDigest: contentDigest,
            minShellIos: minIos, minShellAndroid: minAndroid, issuedAt: issuedAt, keyId: keyId,
            payloadSha256: payloadSha256
        )
    }
}

// MARK: - Canonical ZIP form (manifest v2.0 §5)

nonisolated enum CashTreesPWAZipCanonical {
    static let maxEntries = 10_000
    static let maxTotalUncompressed: UInt64 = 268_435_456
    static let maxNameBytes = 255
    private static let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/@+~-".utf8)
    static let forbiddenNames: Set<String> = [".source.json", ".loaded-sha256", ".loaded-content-sha256"]

    struct Entry: Equatable {
        let name: String
        let method: UInt16
        let crc32: UInt32
        let compressedSize: UInt64
        let uncompressedSize: UInt64
        let localHeaderOffset: UInt64
        let dataOffset: UInt64
    }

    /// Name rules for one entry (file entries only: a trailing "/" is a directory entry and is refused).
    static func nameIsCanonical(_ name: String) -> Bool {
        let bytes = Array(name.utf8)
        guard !bytes.isEmpty, bytes.count <= maxNameBytes, bytes.allSatisfy({ allowed.contains($0) }),
              bytes.first != UInt8(ascii: "/"), bytes.last != UInt8(ascii: "/")
        else { return false }
        let parts = name.split(separator: "/", omittingEmptySubsequences: false)
        if parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." || $0 == "__MACOSX" }) { return false }
        let last = String(parts.last ?? "")
        if last.hasPrefix("._") || forbiddenNames.contains(last) { return false }
        return true
    }

    /// Name-set rules: canonical names, no duplicates, no names equal after ASCII lower-case folding (M3), and a root
    /// index.html and update.json.
    static func check(names: [String]) -> Bool {
        var seen = Set<String>()
        var folded = Set<String>()
        for name in names {
            guard nameIsCanonical(name) else { return false }
            if !seen.insert(name).inserted { return false }
            if !folded.insert(name.lowercased()).inserted { return false }
        }
        return seen.contains("index.html") && seen.contains("update.json")
    }

    private static func u16(_ d: [UInt8], _ o: Int) -> UInt16 { UInt16(d[o]) | UInt16(d[o + 1]) << 8 }
    private static func u32(_ d: [UInt8], _ o: Int) -> UInt32 {
        UInt32(d[o]) | UInt32(d[o + 1]) << 8 | UInt32(d[o + 2]) << 16 | UInt32(d[o + 3]) << 24
    }

    /// Structural parse (M2): the EOCD is exactly the last 22 bytes with a zero-length comment; single disk, no ZIP64;
    /// the central directory directly follows the last entry's data and ends at the EOCD; local headers start at 0 in
    /// central-directory order with no gaps, overlaps or reordering; local and central fields agree; entry comments are
    /// empty; flags only bits 1, 2, 11 (no encryption, no data descriptor); methods 0 or 8; regular files only; limits.
    /// Returns the entries, or nil when anything fails.
    static func parse(zip: URL) -> [Entry]? {
        guard let data = try? Data(contentsOf: zip, options: .mappedIfSafe), data.count >= 22 else { return nil }
        let d = [UInt8](data)
        let n = d.count
        let eocd = n - 22
        guard u32(d, eocd) == 0x0605_4b50, u16(d, eocd + 4) == 0, u16(d, eocd + 6) == 0 else { return nil }
        let entriesOnDisk = Int(u16(d, eocd + 8)), total = Int(u16(d, eocd + 10))
        let cdSize = Int(u32(d, eocd + 12)), cdOffset = Int(u32(d, eocd + 16))
        guard u16(d, eocd + 20) == 0, entriesOnDisk == total, total <= maxEntries, total != 0xFFFF,
              cdSize != 0xFFFF_FFFF, cdOffset != 0xFFFF_FFFF, cdOffset + cdSize == eocd
        else { return nil }
        var entries: [Entry] = []
        var names: [String] = []
        var p = cdOffset
        var expectedLocal = 0
        var totalUncompressed: UInt64 = 0
        for _ in 0..<total {
            guard p + 46 <= eocd, u32(d, p) == 0x0201_4b50 else { return nil }
            let flags = u16(d, p + 8), method = u16(d, p + 10)
            let crc = u32(d, p + 16), csize = u32(d, p + 20), usize = u32(d, p + 24)
            let nameLen = Int(u16(d, p + 28)), extraLen = Int(u16(d, p + 30)), commentLen = Int(u16(d, p + 32))
            let diskStart = u16(d, p + 34), external = u32(d, p + 38), localOffset = Int(u32(d, p + 42))
            guard flags & ~UInt16(0b1000_0000_0110) == 0, method == 0 || method == 8, commentLen == 0, diskStart == 0,
                  csize != 0xFFFF_FFFF, usize != 0xFFFF_FFFF, nameLen <= maxNameBytes,
                  p + 46 + nameLen + extraLen <= eocd
            else { return nil }
            let fileType = (external >> 16) & 0o170000
            guard fileType == 0 || fileType == 0o100000 else { return nil }
            guard let name = String(bytes: d[(p + 46)..<(p + 46 + nameLen)], encoding: .utf8) else { return nil }
            // Local header: exactly where the previous entry's data ended, fields equal to the central directory.
            guard localOffset == expectedLocal, localOffset + 30 <= cdOffset, u32(d, localOffset) == 0x0403_4b50,
                  u16(d, localOffset + 6) == flags, u16(d, localOffset + 8) == method,
                  u32(d, localOffset + 14) == crc, u32(d, localOffset + 18) == csize, u32(d, localOffset + 22) == usize,
                  Int(u16(d, localOffset + 26)) == nameLen
            else { return nil }
            let localExtra = Int(u16(d, localOffset + 28))
            let dataStart = localOffset + 30 + nameLen + localExtra
            guard dataStart <= cdOffset, Array(d[(localOffset + 30)..<(localOffset + 30 + nameLen)]) == Array(d[(p + 46)..<(p + 46 + nameLen)]),
                  dataStart + Int(csize) <= cdOffset
            else { return nil }
            expectedLocal = dataStart + Int(csize)
            totalUncompressed += UInt64(usize)
            guard totalUncompressed <= maxTotalUncompressed else { return nil }
            entries.append(Entry(name: name, method: method, crc32: crc, compressedSize: UInt64(csize),
                                 uncompressedSize: UInt64(usize), localHeaderOffset: UInt64(localOffset), dataOffset: UInt64(dataStart)))
            names.append(name)
            p += 46 + nameLen + extraLen
        }
        guard p == eocd, expectedLocal == cdOffset, check(names: names) else { return nil }
        return entries
    }

    /// Steps 12–13: structural check, then extraction into `dir` with each entry capped at its declared length (an entry
    /// that inflates past it is refused while streaming, never after), no shell marker file present after unpacking,
    /// inner update.json ver equal to the payload ver, and beamio-tree-v1 equal to the payload contentDigest.
    static func extractVerified(zip: URL, to dir: URL, expectedVer: String, expectedContentDigest: String) -> CashTreesPWAOtaVerdict {
        guard let entries = parse(zip: zip), let archive = try? Archive(url: zip, accessMode: .read) else { return .noncanonicalZip }
        let fm = FileManager.default
        try? fm.removeItem(at: dir)
        guard (try? fm.createDirectory(at: dir, withIntermediateDirectories: true)) != nil else { return .noncanonicalZip }
        let byName = Dictionary(uniqueKeysWithValues: archive.map { ($0.path, $0) })
        for entry in entries {
            guard let zipEntry = byName[entry.name] else { return .noncanonicalZip }
            let target = dir.appendingPathComponent(entry.name)
            guard (try? fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)) != nil,
                  fm.createFile(atPath: target.path, contents: nil),
                  let handle = try? FileHandle(forWritingTo: target)
            else { return .noncanonicalZip }
            var written: UInt64 = 0
            var overflow = false
            do {
                _ = try archive.extract(zipEntry, skipCRC32: false) { chunk in
                    written += UInt64(chunk.count)
                    if written > entry.uncompressedSize {
                        overflow = true
                        throw CocoaError(.fileWriteOutOfSpace)
                    }
                    try handle.write(contentsOf: chunk)
                }
            } catch {
                try? handle.close()
                return .noncanonicalZip
            }
            try? handle.close()
            if overflow || written != entry.uncompressedSize { return .noncanonicalZip }
        }
        // The shell's own marker files can only be written by the shell, after this point.
        for marker in forbiddenNames where fm.fileExists(atPath: dir.appendingPathComponent(marker).path) {
            return .noncanonicalZip
        }
        guard let data = try? Data(contentsOf: dir.appendingPathComponent("update.json")),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return .noncanonicalZip }
        guard obj["ver"] as? String == expectedVer else { return .contentMismatch }
        guard CashTreesPWASameVersionRule.treeDigest(at: dir) == expectedContentDigest else { return .contentMismatch }
        return .ok
    }
}

#if BEAMIO_QA_OTA
/// QA-only OTA endpoint and test key (compiled only with BEAMIO_QA_OTA; never in a release or store build). Values come
/// from the QA build's own Info.plist: BeamioQAOtaManifestURL (http://127.0.0.1:<port>/...), BeamioQAOtaPublicKey
/// (base64 raw Ed25519). The test private key lives only in the local stub process.
nonisolated enum CashTreesPWAOtaQA {
    static var manifestURL: URL? {
        guard let s = Bundle.main.object(forInfoDictionaryKey: "BeamioQAOtaManifestURL") as? String,
              let url = URL(string: s), url.scheme == "http", url.host == "127.0.0.1"
        else { return nil }
        return url
    }

    static var publicKey: CashTreesPWAOtaPublicKey? {
        guard let b64 = Bundle.main.object(forInfoDictionaryKey: "BeamioQAOtaPublicKey") as? String,
              let raw = Data(base64Encoded: b64), raw.count == 32
        else { return nil }
        return CashTreesPWAOtaPublicKey(keyId: CashTreesPWAOtaVerifier.keyId(of: raw), publicKeyBase64: b64)
    }
}
#endif
