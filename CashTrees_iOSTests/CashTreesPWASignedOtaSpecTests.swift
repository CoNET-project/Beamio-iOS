//
//  CashTreesPWASignedOtaSpecTests.swift
//  CashTrees_iOSTests
//
//  Manifest v2.0 (revision 1) conformance against the frozen golden vectors, plus the review items: non-canonical
//  signature S, multi-signature binding, size limits, staging re-verification, install-id independence, the decision
//  table hash and the concurrency table.
//
//  The vectors are a test-only copy in Fixtures/ota-manifest-v2-r1 (vectors.json sha256-asserted, zips/), copied into
//  the test bundle as resources. The two vector ZIPs derived from the frozen 0.53.48 ZIP (tampered-zip: one byte XOR 1;
//  truncated-zip: last byte removed) are rebuilt at test time and sha256-asserted. The frozen ZIP is vendored as
//  Fixtures/ota-manifest-v2-r1/golden-SilentPassUI-0.53.48.zip (from 5c3abdd8), accepted only when its sha256 is the
//  frozen one; anything else fails the test (never skipped). The app may embed any PWA.
//

import CryptoKit
import Darwin
import Foundation
import Testing
import ZIPFoundation
@testable import CashTrees_iOS

@Suite(.serialized)
struct CashTreesPWASignedOtaSpecTests {
    private final class BundleToken {}
    static let fixtures = Bundle(for: BundleToken.self)
    static let vectorsSha256 = "747abad22e97da707d45684ec6078fc0abab354405dc7cf228b6d8a4538b8031"
    static let goldenZipSha256 = "c4805a90ae4bbec1ea5f6f3db5cf1674023819fe77fed165287fe54b094f2f19"
    static let derivedZips: [String: (sha256: String, make: (Data) -> Data)] = [
        "zips/tampered-zip.zip": ("1e03d0dd22731c4d3902758cb2fac307edf8391c3635eaf6f426b2486a351d16", { d in
            var t = d; t[5_541_088] ^= 0x01; return t
        }),
        "zips/truncated-zip.zip": ("137d293af20d9d0f29b3f6ca9076e7afb318d069f8ff3f8b2bc20dd10b003150", { d in d.dropLast(1) }),
    ]
    static let derivedDir = OtaBundleFixture.runRoot.appendingPathComponent("vectors-derived", isDirectory: true)

    /// The frozen 0.53.48 ZIP, sha256-checked.
    static func goldenZipURL() throws -> URL {
        // vendored in the test bundle, so the vectors do not depend on the PWA the app embeds
        let url = try #require(fixtures.url(forResource: "golden-SilentPassUI-0.53.48", withExtension: "zip"), "the golden ZIP fixture is missing")
        let sha = CashTreesPWASameVersionRule.fileSHA256(at: url)
        try #require(sha == goldenZipSha256, "the golden ZIP fixture is not the frozen 0.53.48: sha256=\(sha ?? "none")")
        return url
    }

    /// A vector ZIP reference: golden, derived from golden (rebuilt and sha256-checked), or a fixture file.
    /// Removes the rebuilt ZIPs (about 22 MB) at the end of the tests that use them.
    static func removeDerivedZips() {
        try? FileManager.default.removeItem(at: derivedDir)
    }

    static func zipURL(_ ref: String) throws -> URL {
        if ref.hasPrefix("golden:") { return try goldenZipURL() }
        if let derived = derivedZips[ref] {
            let url = derivedDir.appendingPathComponent((ref as NSString).lastPathComponent)
            if !FileManager.default.fileExists(atPath: url.path) {
                let data = derived.make(try Data(contentsOf: try goldenZipURL()))
                try #require(CashTreesPWASameVersionRule.sha256Hex(data) == derived.sha256, "\(ref): rebuilt bytes differ from the sealed vector")
                try FileManager.default.createDirectory(at: derivedDir, withIntermediateDirectories: true)
                try data.write(to: url)
            }
            return url
        }
        let name = (ref as NSString).lastPathComponent
        return try #require(fixtures.url(forResource: (name as NSString).deletingPathExtension, withExtension: "zip"), "fixture \(ref) missing")
    }
    static let goldenContentDigest = "13080eef9cec6068692696a8bd70ff10d19c1cfd9aa815f7c421f24748604974"

    private func loadVectors() throws -> [String: Any] {
        let url = try #require(Self.fixtures.url(forResource: "vectors", withExtension: "json"), "fixture vectors.json missing")
        let data = try Data(contentsOf: url)
        #expect(CashTreesPWASameVersionRule.sha256Hex(data) == Self.vectorsSha256, "vectors.json is not the sealed copy")
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func keys(_ list: Any?) -> [CashTreesPWAOtaPublicKey] {
        ((list as? [[String: Any]]) ?? []).compactMap {
            guard let id = $0["keyId"] as? String, let pk = $0["publicKey"] as? String else { return nil }
            return CashTreesPWAOtaPublicKey(keyId: id, publicKeyBase64: pk)
        }
    }

    // MARK: Golden vectors (45 cases)

    @Test func allSealedVectorsReproduceTheExpectedVerdicts() throws {
        defer { Self.removeDerivedZips() }
        let v = try loadVectors()
        let trusted = keys(v["trustedKeys"])
        #expect(trusted.map(\.keyId) == ["250cf19731885996"])
        #expect(!CashTreesPWAOtaKeys.production.contains { trusted.map(\.keyId).contains($0.keyId) })
        let cases = try #require(v["cases"] as? [[String: Any]])
        #expect(cases.count == 45)
        var passed = 0
        for c in cases {
            let name = c["name"] as? String ?? "?"
            let ctx = c["context"] as? [String: Any] ?? [:]
            let expect = c["expect"] as? [String: Any] ?? [:]
            let verifier = CashTreesPWAOtaVerifier(
                trustedKeys: trusted,
                shellBuild: Int64((ctx["shellBuild"] as? NSNumber)?.int64Value ?? 0),
                platform: ctx["platform"] as? String ?? "ios",
                revoked: Set((ctx["revokedPayloads"] as? [String]) ?? [])
            )
            let updateJson = Data((c["updateJson"] as? String ?? "").utf8)
            let check = verifier.verifyManifest(updateJson, referenceVersion: ctx["referenceVersion"] as? String)
            var ok = check.verdict.rawValue == (expect["manifestVerdict"] as? String)
            #expect(ok, "\(name): manifest \(check.verdict.rawValue) != \(expect["manifestVerdict"] ?? "nil")")
            if let bundleExpect = expect["bundleVerdict"] as? String {
                let manifest = try #require(check.manifest, "\(name): no manifest")
                let zipRef = c["zip"] as? String ?? ""
                let zip = try Self.zipURL(zipRef)
                let work = try OtaBundleFixture.tempDir("vec")
                defer { try? FileManager.default.removeItem(at: work) }
                let bundle = verifier.verifyBundleFull(manifest, zip: zip, workDir: work.appendingPathComponent("x"))
                let bundleOk = bundle.rawValue == bundleExpect
                #expect(bundleOk, "\(name): bundle \(bundle.rawValue) != \(bundleExpect)")
                ok = ok && bundleOk
            } else {
                #expect(expect["bundleVerdict"] == nil || expect["bundleVerdict"] is NSNull, "\(name)")
            }
            if ok { passed += 1 }
        }
        print("[OTA-VECTORS] Fixtures/ota-manifest-v2-r1/vectors.json sha256=\(Self.vectorsSha256) passed=\(passed)/\(cases.count)")
        #expect(passed == 45)
        Self.removeDerivedZips()
        #expect(!FileManager.default.fileExists(atPath: Self.derivedDir.path), "rebuilt ZIPs are removed")
    }

    /// Every noncanonical_zip vector is refused by the structural parse, before any byte is unpacked; the canonical
    /// vector ZIPs pass it.
    @Test func noncanonicalVectorZipsAreRefusedBeforeUnpacking() throws {
        defer { Self.removeDerivedZips() }
        let v = try loadVectors()
        let cases = try #require(v["cases"] as? [[String: Any]])
        var refused = 0
        for c in cases {
            let name = c["name"] as? String ?? "?"
            guard let zipRef = c["zip"] as? String, !zipRef.hasPrefix("golden:") else { continue }
            let expect = (c["expect"] as? [String: Any])?["bundleVerdict"] as? String
            let parsed = CashTreesPWAZipCanonical.parse(zip: try Self.zipURL(zipRef))
            if expect == "noncanonical_zip" {
                #expect(parsed == nil, "\(name): structural parse accepted a noncanonical ZIP")
                if parsed == nil { refused += 1 }
            } else if expect == "ok" {
                #expect(parsed != nil, "\(name): structural parse refused a canonical ZIP")
            }
        }
        print("[OTA-VECTORS-PARSE] noncanonical refused before unpacking=\(refused)")
        #expect(refused == 17)
    }

    @Test func goldenContentDigestIsTheFullLengthValueEverywhere() throws {
        let v = try loadVectors()
        let golden = try #require(v["golden"] as? [String: Any])
        #expect(golden["contentDigest"] as? String == Self.goldenContentDigest)
        let work = try OtaBundleFixture.tempDir("gold"); defer { try? FileManager.default.removeItem(at: work) }
        try FileManager.default.unzipItem(at: try Self.goldenZipURL(), to: work)
        #expect(CashTreesPWASameVersionRule.treeDigest(at: work) == Self.goldenContentDigest)
        // The test host may embed any PWA: its build identity is still the full-length digest (64 lowercase hex), never a prefix.
        let host = NativeBridgeTrust.expectedActiveTreeSHA256
        #expect(host.count == 64 && host.allSatisfy { "0123456789abcdef".contains($0) })
    }

    // MARK: Signatures

    /// Ed25519 group order L (little-endian).
    private static let groupOrderL: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ]

    @Test func nonCanonicalSignatureScalarIsRefused() throws {
        let v = try loadVectors()
        let trusted = keys(v["trustedKeys"])
        let cases = try #require(v["cases"] as? [[String: Any]])
        let golden = try #require(cases.first { $0["name"] as? String == "golden-ok" })
        let doc = try #require(JSONSerialization.jsonObject(with: Data((golden["updateJson"] as? String ?? "").utf8)) as? [String: Any])
        var signed = try #require(doc["signed"] as? [String: Any])
        var sigs = try #require(signed["signatures"] as? [[String: Any]])
        var sig = [UInt8](try #require(Data(base64Encoded: sigs[0]["sig"] as? String ?? "")))
        // S' = S + L (same value mod L, not canonical).
        var carry = 0
        for i in 0..<32 {
            let sum = Int(sig[32 + i]) + Int(Self.groupOrderL[i]) + carry
            sig[32 + i] = UInt8(sum & 0xff)
            carry = sum >> 8
        }
        sigs[0]["sig"] = Data(sig).base64EncodedString()
        signed["signatures"] = sigs
        var out = doc
        out["signed"] = signed
        let data = try JSONSerialization.data(withJSONObject: out)
        let verifier = CashTreesPWAOtaVerifier(trustedKeys: trusted, shellBuild: 114)
        #expect(verifier.verifyManifest(data, referenceVersion: "0.53.47").verdict == .badSignature)
        // The unmodified golden passes with the same verifier.
        #expect(verifier.verifyManifest(Data((golden["updateJson"] as? String ?? "").utf8), referenceVersion: "0.53.47").verdict == .ok)
    }

    @Test func aTrustedSignatureNotBoundToThePayloadNeverPasses() throws {
        let trustedSigner = OtaTestSigner()
        let otherSigner = OtaTestSigner()
        let f = try OtaBundleFixture.make(index: "ms", ver: "0.53.49")
        let payload = f.payload()
        let otherPayload = OtaTestSigner.payload(ver: "0.53.50", filename: "SilentPassUI-0.53.50.zip", sha256: f.zipSha,
                                                 size: f.size, contentDigest: f.tree)
        let signed: [String: Any] = [
            "payload": payload.base64EncodedString(),
            "signatures": [
                // Trusted key, but its signature is over a different payload.
                ["keyId": trustedSigner.publicKey.keyId, "sig": trustedSigner.signature(otherPayload).base64EncodedString()],
                // A valid signature over this payload, from a key that is not trusted.
                ["keyId": otherSigner.publicKey.keyId, "sig": otherSigner.signature(payload).base64EncodedString()],
            ],
        ]
        let json = trustedSigner.updateJson(payload, ver: f.ver, filename: f.filename, signed: signed)
        let v = CashTreesPWAOtaVerifier(trustedKeys: [trustedSigner.publicKey], shellBuild: 999)
        #expect(v.verifyManifest(json, referenceVersion: "0.53.48").verdict == .badSignature)
    }

    /// Aligned with the reference verifier: "signatures" absent (or not an array) is malformed; an empty array is
    /// missing_signature; an absent or null "signed" is missing_signature.
    @Test func absentSignaturesKeyIsMalformed() throws {
        let s = OtaTestSigner()
        let f = try OtaBundleFixture.make(index: "nosig", ver: "0.53.49")
        let p = f.payload()
        let v = CashTreesPWAOtaVerifier(trustedKeys: [s.publicKey], shellBuild: 999)
        func verdict(_ signed: Any?) -> CashTreesPWAOtaVerdict {
            var doc: [String: Any] = ["ver": f.ver, "filename": f.filename]
            if let signed { doc["signed"] = signed }
            let data = try! JSONSerialization.data(withJSONObject: doc, options: [.sortedKeys])
            return v.verifyManifest(data, referenceVersion: "0.53.48").verdict
        }
        #expect(verdict(["payload": p.base64EncodedString()]) == .malformed)
        #expect(verdict(["payload": p.base64EncodedString(), "signatures": NSNull()]) == .malformed)
        #expect(verdict(["payload": p.base64EncodedString(), "signatures": "x"]) == .malformed)
        #expect(verdict(["payload": p.base64EncodedString(), "signatures": [Any]()]) == .missingSignature)
        #expect(verdict(["payload": "%%%", "signatures": [Any]()]) == .missingSignature, "empty array is checked before the payload")
        #expect(verdict(nil) == .missingSignature)
        #expect(verdict(NSNull()) == .missingSignature)
        #expect(verdict(s.signedDict(p)) == .ok)
        // A stored signed object without "signatures" is refused the same way.
        let stored = try JSONSerialization.data(withJSONObject: ["payload": p.base64EncodedString(), "updateVer": f.ver, "updateFilename": f.filename])
        #expect(v.verifySignedObject(stored).verdict == .malformed)
    }

    /// Aligned with the reference verifier: an item whose sig is not strict base64 of exactly 64 bytes is skipped (not a
    /// malformed document); the remaining items still decide. A bad item's keyId still counts as "a trusted key was seen".
    @Test func anUndecodableSignatureItemIsSkipped() throws {
        let s = OtaTestSigner()
        let other = OtaTestSigner()
        let f = try OtaBundleFixture.make(index: "skip", ver: "0.53.49")
        let p = f.payload()
        let good = s.signature(p).base64EncodedString()
        let v = CashTreesPWAOtaVerifier(trustedKeys: [s.publicKey], shellBuild: 999)
        func verdict(_ items: [[String: Any]]) -> CashTreesPWAOtaVerdict {
            let json = s.updateJson(p, ver: f.ver, filename: f.filename, signed: ["payload": p.base64EncodedString(), "signatures": items])
            return v.verifyManifest(json, referenceVersion: "0.53.48").verdict
        }
        let bad: [String] = ["not base64!", Data(repeating: 1, count: 63).base64EncodedString(),
                             Data(repeating: 1, count: 65).base64EncodedString(), String(good.dropLast(2))]
        for b in bad {
            // A bad item before a valid trusted signature: skipped, the document passes.
            #expect(verdict([["keyId": s.publicKey.keyId, "sig": b], ["keyId": s.publicKey.keyId, "sig": good]]) == .ok, "\(b)")
            #expect(verdict([["keyId": other.publicKey.keyId, "sig": b], ["keyId": s.publicKey.keyId, "sig": good]]) == .ok, "\(b)")
            // Only a bad item from a trusted key: bad_signature; only from an untrusted key: untrusted_key.
            #expect(verdict([["keyId": s.publicKey.keyId, "sig": b]]) == .badSignature, "\(b)")
            #expect(verdict([["keyId": other.publicKey.keyId, "sig": b]]) == .untrustedKey, "\(b)")
        }
        // The item shape itself is still strict: a non-string sig or a non-hex keyId makes the document malformed.
        #expect(verdict([["keyId": s.publicKey.keyId, "sig": 5], ["keyId": s.publicKey.keyId, "sig": good]]) == .malformed)
        #expect(verdict([["keyId": "XYZ", "sig": good], ["keyId": s.publicKey.keyId, "sig": good]]) == .malformed)
    }

    @Test func canonicalPayloadBytesAreRequired() throws {
        let s = OtaTestSigner()
        let f = try OtaBundleFixture.make(index: "cb", ver: "0.53.49")
        let v = CashTreesPWAOtaVerifier(trustedKeys: [s.publicKey], shellBuild: 999)
        let good = String(data: f.payload(), encoding: .utf8)!
        let variants = [
            good.replacingOccurrences(of: #""v":2"#, with: #""v":2.0"#),
            good.replacingOccurrences(of: #"{"type""#, with: #"{ "type""#),
            good.replacingOccurrences(of: #""type":"beamio-pwa-ota","v":2"#, with: #""v":2,"type":"beamio-pwa-ota""#),
            good.replacingOccurrences(of: "\"beamio-pwa-ota\"", with: "\"beamio-pwa-ot" + "\\" + "u0061\""),
        ]
        for variant in variants {
            #expect(variant != good, "the variant must differ from the canonical bytes")
            let p = Data(variant.utf8)
            #expect(v.verifyManifest(s.updateJson(p, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .malformed, "\(variant)")
        }
        #expect(v.verifyManifest(s.updateJson(f.payload(), ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .ok)
    }

    // MARK: Size limits

    @Test func zipLargerThanTheShellLimitIsRefusedBeforeDownload() {
        #expect(CashTreesPWAOtaVerifier.maxZipBytes == 128 * 1024 * 1024)
        #expect(CashTreesPWAOtaVerdict.tooLarge.statusClass == "rejected-integrity")
    }

    @Test func downloadStopsAsSoonAsItPassesThePayloadSize() async throws {
        let out = OtaBundleFixture.runRoot.appendingPathComponent("bounded-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: out.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: out) }
        let handle = try FileHandle(forWritingTo: out)
        let stream = AsyncStream<UInt8> { continuation in
            for _ in 0..<1000 { continuation.yield(0x41) }
            continuation.finish()
        }
        await #expect(throws: CashTreesPWADownloadError.self) {
            try await CashTreesPWABoundedWriter.copy(stream, to: handle, maxBytes: 999)
        }
        try handle.close()
        let written = (try FileManager.default.attributesOfItem(atPath: out.path)[.size] as? NSNumber)?.intValue ?? -1
        #expect(written <= 999)
        // Exactly the declared size is fine.
        let out2 = OtaBundleFixture.runRoot.appendingPathComponent("bounded2-\(UUID().uuidString)")
        FileManager.default.createFile(atPath: out2.path, contents: nil)
        defer { try? FileManager.default.removeItem(at: out2) }
        let h2 = try FileHandle(forWritingTo: out2)
        let s2 = AsyncStream<UInt8> { c in for _ in 0..<1000 { c.yield(0x41) }; c.finish() }
        try await CashTreesPWABoundedWriter.copy(s2, to: h2, maxBytes: 1000)
        try h2.close()
    }

    /// Patches the declared uncompressed size of the first entry (local header and central directory together).
    private func patchFirstEntryUncompressedSize(_ zip: URL, to newSize: UInt32) throws {
        var d = [UInt8](try Data(contentsOf: zip))
        func put(_ o: Int, _ v: UInt32) { for i in 0..<4 { d[o + i] = UInt8((v >> (8 * UInt32(i))) & 0xff) } }
        put(22, newSize) // local header uncompressed size
        let eocd = d.count - 22
        let cd = Int(UInt32(d[eocd + 16]) | UInt32(d[eocd + 17]) << 8 | UInt32(d[eocd + 18]) << 16 | UInt32(d[eocd + 19]) << 24)
        put(cd + 24, newSize)
        try Data(d).write(to: zip)
    }

    @Test func extractionIsCappedAtTheDeclaredLength() throws {
        // A canonical deflate entry that inflates past its declared length: refused while streaming.
        let src = try OtaBundleFixture.tempDir("bomb")
        try Data(String(repeating: "A", count: 200_000).utf8).write(to: src.appendingPathComponent("a.js"))
        try Data("<html></html>".utf8).write(to: src.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"0.53.49\"}".utf8).write(to: src.appendingPathComponent("update.json"))
        let zip = src.deletingLastPathComponent().appendingPathComponent("bomb-\(UUID().uuidString).zip")
        let archive = try Archive(url: zip, accessMode: .create)
        for name in ["a.js", "index.html", "update.json"] {
            try archive.addEntry(with: name, relativeTo: src, compressionMethod: .deflate)
        }
        #expect(CashTreesPWAZipCanonical.parse(zip: zip) != nil, "the unpatched fixture is canonical")
        try patchFirstEntryUncompressedSize(zip, to: 1000)
        #expect(CashTreesPWAZipCanonical.parse(zip: zip) != nil, "declared sizes agree, so the structure still passes")
        let work = try OtaBundleFixture.tempDir("bombx"); defer { try? FileManager.default.removeItem(at: work) }
        let out = work.appendingPathComponent("x")
        #expect(CashTreesPWAZipCanonical.extractVerified(zip: zip, to: out, expectedVer: "0.53.49",
                                                         expectedContentDigest: String(repeating: "0", count: 64)) == .noncanonicalZip)
        let size = (try? FileManager.default.attributesOfItem(atPath: out.appendingPathComponent("a.js").path)[.size] as? NSNumber)?.intValue ?? 0
        #expect(size <= 1000, "never written past the declared length")
    }

    // MARK: Q3 / Q5

    @Test func replacedStagingCannotUseTheOldSignedObject() throws {
        let r = try OtaBundleFixture.tempDir("q3"); defer { try? FileManager.default.removeItem(at: r) }
        let signer = OtaTestSigner()
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let s49 = try OtaBundleFixture.make(index: "s-49", ver: "0.53.49")
        let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        try s49.placeSignedStaging(root: r, signer: signer)
        // Replace the staging content (same version), keep the old signed object.
        try Data("console.log('swapped')".utf8).write(to: store.stagingDir.appendingPathComponent("static/js/main.js"))
        #expect(throws: (any Error).self) { try store.promoteStagingToActive() }
        #expect(store.activeVersion() == "0.53.48")
        // An unverifiable local + the swapped staging: the staging is not a candidate.
        try OtaBundleFixture.writeTree(store.activeDir, index: "tampered", ver: "0.53.60")
        try s49.placeSignedStaging(root: r, signer: signer)
        try Data("console.log('swapped')".utf8).write(to: store.stagingDir.appendingPathComponent("static/js/main.js"))
        let o = try CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.decision == "repaired-unverifiable" && o.selectedOrigin == "embedded")
    }

    /// The whole bundle root stays out of iCloud and device-transfer backups, set on the first cold start and put back
    /// by the next one (fast path, unchanged) when it is missing.
    @Test func bundleRootIsExcludedFromBackup() throws {
        let r = try OtaBundleFixture.tempDir("bk"); defer { try? FileManager.default.removeItem(at: r) }
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        func excluded() throws -> Bool {
            var url = r
            url.removeAllCachedResourceValues()
            return try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true
        }
        #expect(try !excluded(), "a fresh temporary directory is backed up by default")
        let first = try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(first.path == .full)
        #expect(try excluded())
        // Cleared (for example by a restore of the parent): the next cold start sets it again and still takes the fast path.
        var url = r
        var values = URLResourceValues()
        values.isExcludedFromBackup = false
        try url.setResourceValues(values)
        #expect(try !excluded())
        let second = try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(second.path == .fast)
        #expect(second.unpackCount == 0 && second.versionCompareCount == 0 && second.zipReadCount == 0 && second.fullDigestCount == 0 && !second.recordWritten)
        #expect(try excluded())
        // Its contents (active tree, record, install id) are under the excluded directory.
        for name in ["active", "coldstart-record.v2.json", "install-id.v1"] {
            #expect(FileManager.default.fileExists(atPath: r.appendingPathComponent(name).path), "\(name)")
        }
    }

    @Test func installIdSurvivesEveryRepairPathAndNeverAffectsTrust() throws {
        let r = try OtaBundleFixture.tempDir("q5"); defer { try? FileManager.default.removeItem(at: r) }
        let signer = OtaTestSigner()
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let ota = try OtaBundleFixture.make(index: "ota-49", ver: "0.53.49")
        let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        let id = try #require(CashTreesPWAInstallIdentity.read(root: r))
        // Repair (unverifiable local), record invalidation, interrupted-swap recovery, warm-up failure, retry.
        try OtaBundleFixture.writeTree(store.activeDir, index: "tampered", ver: "0.53.60")
        try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        CashTreesPWAColdStartRecordIO.invalidate(root: r)
        store.recoverInterruptedSwap()
        try Data("x".utf8).write(to: store.activeDir.appendingPathComponent("static/js/main.js"))
        _ = store.warmUpTrust(expectedEmbeddedTree: emb.tree) { CashTreesPWASameVersionRule.treeDigest(at: $0) }
        try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(CashTreesPWAInstallIdentity.read(root: r) == id)
        // Trust does not depend on the install id: replacing it changes no identity resolution.
        try ota.placeSignedActive(root: r, signer: signer)
        let digest: (URL) -> String? = { CashTreesPWASameVersionRule.treeDigest(at: $0) }
        let s1 = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        let before = s1.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest)
        try Data(String(repeating: "b", count: 32).utf8).write(to: r.appendingPathComponent("install-id.v1"))
        let s2 = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        #expect(s2.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest)?.origin == before?.origin)
        #expect(before?.origin == "ota")
        try FileManager.default.removeItem(at: r.appendingPathComponent("install-id.v1"))
        let s3 = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        #expect(s3.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest)?.origin == "ota")
    }

    // MARK: Decision table hash (R5)

    /// Any change to the selection table changes this hash. When it fails, bump CashTreesPWAColdStartRecord.ruleVersion
    /// together with the new expected value.
    @Test func decisionTableHashIsPinnedToTheRuleVersion() {
        typealias S = CashTreesPWACandidateSelector
        let locals: [S.Local] = [.none, .unverifiable, .verifiedEmbedded(ver: "0.53.48"),
                                 .verifiedOta(ver: "0.53.47"), .verifiedOta(ver: "0.53.48"), .verifiedOta(ver: "0.53.49")]
        let embeddeds: [S.Embedded] = [.unusable, .ok(ver: nil), .ok(ver: "0.53.47"), .ok(ver: "0.53.48"), .ok(ver: "0.53.49")]
        let stageds: [S.Staged] = [.none, .verified(ver: "0.53.47"), .verified(ver: "0.53.48"), .verified(ver: "0.53.50")]
        var lines: [String] = []
        for l in locals { for e in embeddeds { for s in stageds {
            lines.append("\(l)|\(e)|\(s)=>\(S.select(local: l, embedded: e, staged: s))")
        } } }
        let hash = CashTreesPWASameVersionRule.sha256Hex(Data(lines.joined(separator: "\n").utf8))
        print("[DECISION-TABLE] ruleVersion=\(CashTreesPWAColdStartRecord.ruleVersion) cases=\(lines.count) sha256=\(hash)")
        #expect(CashTreesPWAColdStartRecord.ruleVersion == 2)
        #expect(hash == Self.decisionTableSha256V2, "selection table changed: bump ruleVersion and update the pinned hash")
    }

    static let decisionTableSha256V2 = "1d60d12d0e87f1d6ccedb2a63fd9f6a0f848912daa84ce46e47616a5508c53ad"

    // MARK: Concurrency table C1a–C5

    @Test func c1aOwnPartialSurvivesTheFullPassForeignIsRemoved() throws {
        let r = try OtaBundleFixture.tempDir("c1a"); defer { try? FileManager.default.removeItem(at: r) }
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: r)
        let own = r.appendingPathComponent(".staging-partial-\(store.processInstance)")
        let foreign = r.appendingPathComponent(".staging-partial-OTHER")
        try FileManager.default.createDirectory(at: own, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: foreign, withIntermediateDirectories: true)
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(FileManager.default.fileExists(atPath: own.path), "a download in progress in this process is not disturbed")
        #expect(!FileManager.default.fileExists(atPath: foreign.path))
        #expect(store.lastColdStart.recordWritten)
    }

    @Test func c2ToC4OtaSwitchesNewShellsAndKeyRotation() throws {
        let signer = OtaTestSigner()
        let e47 = try OtaBundleFixture.make(index: "emb-47", ver: "0.53.47")
        let e50 = try OtaBundleFixture.make(index: "emb-50", ver: "0.53.50")
        let ota48 = try OtaBundleFixture.make(index: "ota-48", ver: "0.53.48")
        let ota49 = try OtaBundleFixture.make(index: "ota-49", ver: "0.53.49")
        let s51 = try OtaBundleFixture.make(index: "s-51", ver: "0.53.51")
        let s45 = try OtaBundleFixture.make(index: "s-45", ver: "0.53.45")
        func index(_ store: CashTreesPWABundleStore) -> String? {
            try? String(contentsOf: store.activeDir.appendingPathComponent("index.html"), encoding: .utf8)
        }
        // C2: an OTA switch between cold starts: the record is deleted; the next start classifies V-ota and records it.
        do {
            let r = try OtaBundleFixture.tempDir("c2"); defer { try? FileManager.default.removeItem(at: r) }
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            try store.coldStart(bundledZip: e47.zip, facts: e47.facts, shellBuild: "114")
            try ota49.placeSignedStaging(root: r, signer: signer)
            try store.promoteStagingToActive()
            #expect(CashTreesPWAColdStartRecordIO.read(root: r) == nil)
            let o = try CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]).coldStart(bundledZip: e47.zip, facts: e47.facts, shellBuild: "114")
            #expect(o.selectedOrigin == "ota" && o.decision == "embedded-older-ignored")
        }
        // C3a: new shell, newer embedded, older signed staging: install the embedded build, drop the staging.
        do {
            let r = try OtaBundleFixture.tempDir("c3a"); defer { try? FileManager.default.removeItem(at: r) }
            try ota48.placeSignedActive(root: r, signer: signer)
            try s45.placeSignedStaging(root: r, signer: signer)
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            let o = try store.coldStart(bundledZip: e50.zip, facts: e50.facts, shellBuild: "115")
            #expect(o.decision == "installed-newer" && index(store) == "emb-50")
            #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path))
        }
        // C3b: new shell, newer embedded, newer signed staging: install the embedded build, keep the staging for apply.
        do {
            let r = try OtaBundleFixture.tempDir("c3b"); defer { try? FileManager.default.removeItem(at: r) }
            try ota48.placeSignedActive(root: r, signer: signer)
            try s51.placeSignedStaging(root: r, signer: signer)
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            let o = try store.coldStart(bundledZip: e50.zip, facts: e50.facts, shellBuild: "115")
            #expect(o.decision == "installed-newer" && index(store) == "emb-50")
            #expect(store.pendingUpdateVersion() == "0.53.51")
        }
        // C3c: the key was rotated out: the old OTA active is unverifiable (repaired) and its old staging is dropped.
        do {
            let r = try OtaBundleFixture.tempDir("c3c"); defer { try? FileManager.default.removeItem(at: r) }
            try ota48.placeSignedActive(root: r, signer: signer)
            try s51.placeSignedStaging(root: r, signer: signer)
            let rotated = OtaTestSigner()
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [rotated.publicKey])
            let o = try store.coldStart(bundledZip: e47.zip, facts: e47.facts, shellBuild: "115")
            #expect(o.decision == "repaired-unverifiable" && index(store) == "emb-47")
            #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path))
        }
        // C4: embedded older than the verified OTA local, a newer signed staging: older-ignored, staging kept for apply.
        do {
            let r = try OtaBundleFixture.tempDir("c4"); defer { try? FileManager.default.removeItem(at: r) }
            try ota49.placeSignedActive(root: r, signer: signer)
            try s51.placeSignedStaging(root: r, signer: signer)
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            let o = try store.coldStart(bundledZip: e47.zip, facts: e47.facts, shellBuild: "115")
            #expect(o.decision == "embedded-older-ignored" && o.embeddedOutcome == "older-ignored" && index(store) == "ota-49")
            #expect(store.pendingUpdateVersion() == "0.53.51")
        }
        // C5 (cold start vs warm-up / gate check) is covered by gateCheckDuringWarmUpWaitsAndReusesTheResult.
    }
}
