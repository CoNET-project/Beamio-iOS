//
//  CashTreesPWASignedOtaTests.swift
//  CashTrees_iOSTests
//
//  Signed OTA (manifest v2), candidate selection, "compared but not enabled" records, install identity and the
//  bridge identity of a signed OTA tree. Test keys are generated in memory per test.
//

import CryptoKit
import Darwin
import Foundation
import Testing
import ZIPFoundation
@testable import CashTrees_iOS

@Suite(.serialized)
struct CashTreesPWASignedOtaTests {
    private func root() throws -> URL { try OtaBundleFixture.tempDir("pwa-r3") }

    private func index(_ store: CashTreesPWABundleStore) -> String? {
        try? String(contentsOf: store.activeDir.appendingPathComponent("index.html"), encoding: .utf8)
    }

    private func record(_ root: URL) -> CashTreesPWAColdStartRecord? { CashTreesPWAColdStartRecordIO.read(root: root) }

    private let digest: (URL) -> String? = { CashTreesPWASameVersionRule.treeDigest(at: $0) }

    // MARK: Verifier v2

    @Test func manifestV2VerdictsCoverEveryRefusal() throws {
        let signer = OtaTestSigner()
        let other = OtaTestSigner()
        let f = try OtaBundleFixture.make(index: "m", ver: "0.53.49")
        let v = CashTreesPWAOtaVerifier(trustedKeys: [signer.publicKey], shellBuild: 114)
        let good = f.payload()
        #expect(v.verifyManifest(signer.updateJson(good, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .ok)
        // Missing signature.
        let unsigned = try JSONSerialization.data(withJSONObject: ["ver": f.ver, "filename": f.filename])
        #expect(v.verifyManifest(unsigned, referenceVersion: "0.53.48").verdict == .missingSignature)
        // Unknown key.
        #expect(v.verifyManifest(other.updateJson(good, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .untrustedKey)
        // Bad signature from a trusted key id.
        let forged = signer.signedDict(good, signature: other.signature(good))
        #expect(v.verifyManifest(signer.updateJson(good, ver: f.ver, filename: f.filename, signed: forged), referenceVersion: "0.53.48").verdict == .badSignature)
        // v1 domain signature is refused (bad signature under the v2 domain).
        let v1sig = signer.signedDict(good, signature: signer.signature(good, domain: "beamio-pwa-ota/v1\n"))
        #expect(v.verifyManifest(signer.updateJson(good, ver: f.ver, filename: f.filename, signed: v1sig), referenceVersion: "0.53.48").verdict == .badSignature)
        // v1 payload (v=1) is malformed for this shell.
        let p1 = OtaTestSigner.payload(ver: f.ver, filename: f.filename, sha256: f.zipSha, size: f.size, contentDigest: f.tree, v: 1)
        #expect(v.verifyManifest(signer.updateJson(p1, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .malformed)
        // Wrong content algorithm.
        let pAlg = OtaTestSigner.payload(ver: f.ver, filename: f.filename, sha256: f.zipSha, size: f.size, contentDigest: f.tree, contentAlg: "other")
        #expect(v.verifyManifest(signer.updateJson(pAlg, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .malformed)
        // Outer ver mismatch.
        #expect(v.verifyManifest(signer.updateJson(good, ver: "0.53.50", filename: f.filename), referenceVersion: "0.53.48").verdict == .mismatch)
        // Non-strict version in the payload.
        let pRc = OtaTestSigner.payload(ver: "0.53.49-rc", filename: f.filename, sha256: f.zipSha, size: f.size, contentDigest: f.tree)
        #expect(v.verifyManifest(signer.updateJson(pRc, ver: "0.53.49-rc", filename: f.filename), referenceVersion: "0.53.48").verdict == .malformed)
        // Downgrade against the verified reference.
        #expect(v.verifyManifest(signer.updateJson(good, ver: f.ver, filename: f.filename), referenceVersion: "0.53.49").verdict == .downgrade)
        // Minimum shell.
        let pMin = f.payload(minIos: 200)
        #expect(v.verifyManifest(signer.updateJson(pMin, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .shellTooOld)
        // Revoked payload.
        let hash = CashTreesPWASameVersionRule.sha256Hex(good)
        let revoking = CashTreesPWAOtaVerifier(trustedKeys: [signer.publicKey], shellBuild: 114, revoked: [hash])
        #expect(revoking.verifyManifest(signer.updateJson(good, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .revoked)
        // ZIP integrity.
        let manifest = try #require(v.verifyManifest(signer.updateJson(good, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").manifest)
        #expect(v.verifyBundle(manifest, zip: f.zip) == .ok)
        let other2 = try OtaBundleFixture.make(index: "different", ver: "0.53.49")
        #expect(v.verifyBundle(manifest, zip: other2.zip) != .ok)
        // Empty key table: nothing is ever trusted.
        let empty = CashTreesPWAOtaVerifier(trustedKeys: [], shellBuild: 114)
        #expect(empty.verifyManifest(signer.updateJson(good, ver: f.ver, filename: f.filename), referenceVersion: "0.53.48").verdict == .untrustedKey)
        #expect(CashTreesPWAOtaKeys.production.isEmpty)
        #expect(CashTreesPWAOtaPolicy.enforce)
    }

    @Test func canonicalZipNameRules() {
        func ok(_ names: [String]) -> Bool { CashTreesPWAZipCanonical.check(names: names) }
        let base = ["index.html", "update.json", "static/js/a.js"]
        #expect(ok(base))
        #expect(!ok(base + ["static/"]), "no directory entries")
        #expect(!ok(base + ["../x"]))
        #expect(!ok(base + ["/abs"]))
        #expect(!ok(base + ["a//b"]))
        #expect(!ok(base + ["a\\b"]))
        #expect(!ok(base + ["__MACOSX/x"]))
        #expect(!ok(base + ["static/._a.js"]))
        #expect(!ok(base + [".source.json"]))
        #expect(!ok(base + ["index.html"]), "duplicate")
        #expect(!ok(base + ["Index.html"]), "case-only duplicate")
        #expect(!ok(base + ["static/JS/a.js"]), "case-only duplicate path")
        #expect(!ok(["index.html"]))
        #expect(!ok(base + ["sp ace.js"]))
        #expect(!ok(base + [String(repeating: "a", count: 256)]))
        #expect(ok(base + [String(repeating: "a", count: 255)]))
    }

    // MARK: Selector

    @Test func selectorTable() {
        typealias S = CashTreesPWACandidateSelector
        let E48 = S.Embedded.ok(ver: "0.53.48")
        let E47 = S.Embedded.ok(ver: "0.53.47")
        let E49 = S.Embedded.ok(ver: "0.53.49")
        #expect(S.select(local: .none, embedded: E48, staged: .none) == .installEmbedded(decision: "installed-first"))
        #expect(S.select(local: .none, embedded: E48, staged: .verified(ver: "0.53.49")) == .promoteStaged(decision: "selected-ota-over-embedded"))
        #expect(S.select(local: .none, embedded: E48, staged: .verified(ver: "0.53.48")) == .installEmbedded(decision: "installed-first"))
        #expect(S.select(local: .none, embedded: .unusable, staged: .verified(ver: "0.53.40")) == .promoteStaged(decision: "selected-ota-over-embedded"))
        #expect(S.select(local: .none, embedded: .unusable, staged: .none) == .noTrustedCandidate)
        #expect(S.select(local: .verifiedEmbedded(ver: "0.53.48"), embedded: E48, staged: .verified(ver: "0.53.49")) == .keepLocal(decision: "kept-identical", embeddedOutcome: "identical"))
        #expect(S.select(local: .verifiedOta(ver: "0.53.48"), embedded: E49, staged: .none) == .installEmbedded(decision: "installed-newer"))
        #expect(S.select(local: .verifiedOta(ver: "0.53.48"), embedded: E48, staged: .none) == .keepLocal(decision: "embedded-same-ignored", embeddedOutcome: "same-version-ignored"))
        #expect(S.select(local: .verifiedOta(ver: "0.53.48"), embedded: E47, staged: .none) == .keepLocal(decision: "embedded-older-ignored", embeddedOutcome: "older-ignored"))
        #expect(S.select(local: .verifiedOta(ver: "0.53.48"), embedded: .unusable, staged: .none) == .keepLocalNoRecord)
        #expect(S.select(local: .verifiedOta(ver: "0.53.48"), embedded: .ok(ver: nil), staged: .none) == .keepLocal(decision: "embedded-ver-unknown", embeddedOutcome: "ver-unknown"))
        #expect(S.select(local: .unverifiable, embedded: E48, staged: .none) == .installEmbedded(decision: "repaired-unverifiable"))
        #expect(S.select(local: .unverifiable, embedded: E48, staged: .verified(ver: "0.53.49")) == .promoteStaged(decision: "selected-ota-over-embedded"))
        #expect(S.select(local: .unverifiable, embedded: E48, staged: .verified(ver: "0.53.48")) == .installEmbedded(decision: "repaired-unverifiable"))
        #expect(S.select(local: .unverifiable, embedded: E48, staged: .verified(ver: "0.53.47")) == .installEmbedded(decision: "repaired-unverifiable"))
        #expect(S.select(local: .unverifiable, embedded: .unusable, staged: .verified(ver: "0.53.47")) == .promoteStaged(decision: "selected-ota-over-embedded"))
        #expect(S.select(local: .unverifiable, embedded: .unusable, staged: .none) == .noTrustedCandidate)
        #expect(CashTreesPWAColdStartRecord.ruleVersion == 2)
    }

    // MARK: Older embedded ignored, then 0/0/0

    @Test func olderEmbeddedIsIgnoredAndTheSecondStartIsZero() throws {
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let signer = OtaTestSigner()
        let ota = try OtaBundleFixture.make(index: "ota-49", ver: "0.53.49")
        let emb = try OtaBundleFixture.make(index: "emb-47", ver: "0.53.47")
        try ota.placeSignedActive(root: r, signer: signer)
        let s1 = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        let o1 = try s1.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o1.decision == "embedded-older-ignored", "\(o1.logLine)")
        #expect(o1.embeddedOutcome == "older-ignored")
        #expect(o1.selectedOrigin == "ota")
        #expect(o1.zipReadCount == 1 && o1.unpackCount == 0 && o1.versionCompareCount == 1)
        #expect(o1.recordWritten)
        #expect(index(s1) == "ota-49")
        let bytes = try Data(contentsOf: CashTreesPWAColdStartRecordIO.recordURL(root: r))
        let rec = try #require(record(r))
        #expect(rec.selected.ota?.signedFile == "ota-signed/\(ota.tree).json")
        #expect(rec.selected.ota?.keyTableId == CashTreesPWAOtaKeys.tableId([signer.publicKey]))
        let sigBefore = CashTreesPWAVersion.compareCount
        let s2 = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        let o2 = try s2.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o2.path == .fast, "\(o2.logLine)")
        #expect(o2.zipReadCount == 0 && o2.unpackCount == 0 && o2.versionCompareCount == 0 && o2.fullDigestCount == 0)
        #expect(s2.signatureChecks == 0)
        #expect(CashTreesPWAVersion.compareCount == sigBefore)
        #expect(try Data(contentsOf: CashTreesPWAColdStartRecordIO.recordURL(root: r)) == bytes)
        // The bridge identity of the OTA tree (warm-up: one digest, one signature check).
        let warm = s2.warmUpTrust(expectedEmbeddedTree: emb.tree, digest: digest)
        #expect(warm.trusted)
        #expect(s2.signatureChecks == 1)
        let resolved = s2.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest)
        #expect(resolved?.origin == "ota")
        #expect(resolved?.version == "0.53.49")
        #expect(resolved?.tree == ota.tree)
    }

    @Test func sameVersionDifferentContentIsIgnoredAndIdenticalIsKept() throws {
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let signer = OtaTestSigner()
        let ota = try OtaBundleFixture.make(index: "ota-48", ver: "0.53.48")
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        try ota.placeSignedActive(root: r, signer: signer)
        let o = try CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.decision == "embedded-same-ignored")
        #expect(o.unpackCount == 0)
        // Same content as the embedded build (only the ZIP container differs): kept-identical, no ZIP read, no unpack.
        let r2 = try root(); defer { try? FileManager.default.removeItem(at: r2) }
        try FileManager.default.copyItem(at: emb.dir, to: r2.appendingPathComponent("active"))
        let o2 = try CashTreesPWABundleStore(testRootDir: r2).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o2.decision == "kept-identical" && o2.unpackCount == 0 && o2.zipReadCount == 0)
    }

    @Test func newerEmbeddedReplacesAVerifiedOtaLocal() throws {
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let signer = OtaTestSigner()
        let ota = try OtaBundleFixture.make(index: "ota-48", ver: "0.53.48")
        let emb = try OtaBundleFixture.make(index: "emb-50", ver: "0.53.50")
        try ota.placeSignedActive(root: r, signer: signer)
        let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        let o = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.decision == "installed-newer" && o.unpackCount == 1 && o.selectedOrigin == "embedded")
        #expect(index(store) == "emb-50")
    }

    // MARK: Reinstall resets

    @Test func newInstallIdForcesANewDecisionAndUnknownIdWritesNoRecord() throws {
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let emb = try OtaBundleFixture.make(index: "e48", ver: "0.53.48")
        let s1 = CashTreesPWABundleStore(testRootDir: r)
        try s1.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        let id1 = try #require(CashTreesPWAInstallIdentity.read(root: r))
        var values = try r.appendingPathComponent("install-id.v1").resourceValues(forKeys: [.isExcludedFromBackupKey])
        #expect(values.isExcludedFromBackup == true)
        values = URLResourceValues()
        // Simulated reinstall: the container (and its id) is new, the data was restored.
        try FileManager.default.removeItem(at: r.appendingPathComponent("install-id.v1"))
        let o = try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.path == .full && o.reason == "install-unknown")
        let id2 = try #require(CashTreesPWAInstallIdentity.read(root: r))
        #expect(id1 != id2)
        #expect(o.recordWritten)
        try Data(String(repeating: "a", count: 32).utf8).write(to: r.appendingPathComponent("install-id.v1"))
        let o2 = try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o2.reason == "install-changed")
        // Identity cannot be created (read-only root, no id): full pass, no record.
        let r3 = try root()
        defer { chmod(r3.path, 0o755); try? FileManager.default.removeItem(at: r3) }
        try FileManager.default.copyItem(at: emb.dir, to: r3.appendingPathComponent("active"))
        #expect(chmod(r3.path, 0o555) == 0)
        let o3 = try CashTreesPWABundleStore(testRootDir: r3).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o3.decision == "kept-identical")
        #expect(!o3.recordWritten)
    }

    @Test func ruleVersionChangeMisses() throws {
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let emb = try OtaBundleFixture.make(index: "e48", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        let url = CashTreesPWAColdStartRecordIO.recordURL(root: r)
        let text = try String(contentsOf: url, encoding: .utf8).replacingOccurrences(of: "\"ruleVersion\":2", with: "\"ruleVersion\":1")
        try Data(text.utf8).write(to: url)
        let o = try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.reason == "rule-changed")
    }

    @Test func legacyV1RecordIsDeletedAndNeverRead() throws {
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let emb = try OtaBundleFixture.make(index: "e48", ver: "0.53.48")
        try FileManager.default.copyItem(at: emb.dir, to: r.appendingPathComponent("active"))
        try Data("{\"schema\":\"beamio.pwa.coldstart.v1\"}".utf8).write(to: r.appendingPathComponent("coldstart-record.v1.json"))
        let o = try CashTreesPWABundleStore(testRootDir: r).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.reason == "no-record" && o.decision == "kept-identical" && o.unpackCount == 0)
        #expect(!FileManager.default.fileExists(atPath: r.appendingPathComponent("coldstart-record.v1.json").path))
    }

    // MARK: Embedded x signed network combinations (local unverifiable)

    @Test func unverifiableLocalTakesTheHigherVerifiedCandidate() throws {
        let signer = OtaTestSigner()
        let emb48 = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let cases: [(String, String, String, String)] = [
            // (staged ver, expected active index, decision, origin)
            ("0.53.49", "s-0.53.49", "selected-ota-over-embedded", "ota"),
            ("0.53.48", "emb-48", "repaired-unverifiable", "embedded"),
            ("0.53.47", "emb-48", "repaired-unverifiable", "embedded"),
        ]
        for (sver, expectedIndex, decision, origin) in cases {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            try OtaBundleFixture.writeTree(store.activeDir, index: "tampered", ver: "0.53.60")
            let s = try OtaBundleFixture.make(index: "s-\(sver)", ver: sver)
            try s.placeSignedStaging(root: r, signer: signer)
            let o = try store.coldStart(bundledZip: emb48.zip, facts: emb48.facts, shellBuild: "114")
            #expect(index(store) == expectedIndex, "\(sver): \(o.logLine)")
            #expect(o.decision == decision, "\(sver)")
            #expect(o.selectedOrigin == origin, "\(sver)")
            if origin == "ota" { #expect(o.unpackCount == 0 && o.embeddedOutcome == "not-selected") }
            #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path), "\(sver): staging consumed or dropped")
            // Second start is fast for both origins.
            let o2 = try CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]).coldStart(bundledZip: emb48.zip, facts: emb48.facts, shellBuild: "114")
            #expect(o2.path == .fast, "\(sver): \(o2.logLine)")
        }
        // Unusable embedded ZIP + signed staging older than the build constant: the signed staging is taken.
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        let s = try OtaBundleFixture.make(index: "s-old", ver: "0.53.40")
        try s.placeSignedStaging(root: r, signer: signer)
        let bad = CashTreesPWAEmbeddedFacts(ver: "0.53.48", zipSha256: String(repeating: "0", count: 64), treeDigest: emb48.tree)
        let o = try store.coldStart(bundledZip: emb48.zip, facts: bad, shellBuild: "114")
        #expect(o.decision == "selected-ota-over-embedded" && index(store) == "s-old")
    }

    @Test func untrustedStagingNeverCompetesAndIsRemoved() throws {
        let signer = OtaTestSigner()
        let other = OtaTestSigner()
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let s = try OtaBundleFixture.make(index: "s-49", ver: "0.53.49")
        // Signed by an unknown key; legacy sig:"ok" and ota-verified/ markers present: none of them is trusted.
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        try OtaBundleFixture.writeTree(store.activeDir, index: "tampered", ver: "0.53.60")
        try s.placeSignedStaging(root: r, signer: other)
        try Data("{\"ver\":\"0.53.49\",\"filename\":\"x.zip\",\"sig\":\"ok\"}".utf8).write(to: store.stagingDir.appendingPathComponent("update.json"))
        try FileManager.default.createDirectory(at: r.appendingPathComponent("ota-verified"), withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: r.appendingPathComponent("ota-verified/\(s.tree).json"))
        let o = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.decision == "repaired-unverifiable" && index(store) == "emb-48")
        #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path))
        // A signed object whose contentDigest does not match the staged tree is not a candidate either.
        let r2 = try root(); defer { try? FileManager.default.removeItem(at: r2) }
        let store2 = CashTreesPWABundleStore(testRootDir: r2, otaKeys: [signer.publicKey])
        try s.placeSignedStaging(root: r2, signer: signer)
        try Data("tampered".utf8).write(to: store2.stagingDir.appendingPathComponent("static/js/main.js"))
        let o2 = try store2.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o2.decision == "installed-first" && index(store2) == "emb-48")
    }

    @Test func networkStatusIsRecordedButNeverChangesSelection() throws {
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let emb = try OtaBundleFixture.make(index: "e48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: r)
        try FileManager.default.createDirectory(at: r, withIntermediateDirectories: true)
        store.writeOtaStatus(result: "network-error", verdict: nil, ver: nil)
        let o = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.network == "network-error")
        #expect(o.decision == "installed-first")
        #expect(record(r)?.network == "network-error")
    }

    // MARK: Bridge identity

    @Test func otaIdentityFailsClosedOnEveryMismatch() throws {
        let signer = OtaTestSigner()
        let emb = try OtaBundleFixture.make(index: "emb-47", ver: "0.53.47")
        let ota = try OtaBundleFixture.make(index: "ota-49", ver: "0.53.49")
        func setup() throws -> (URL, CashTreesPWABundleStore) {
            let r = try root()
            try ota.placeSignedActive(root: r, signer: signer)
            return (r, CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]))
        }
        // Baseline: trusted.
        do {
            let (r, s) = try setup(); defer { try? FileManager.default.removeItem(at: r) }
            #expect(s.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest)?.origin == "ota")
        }
        // Tampered active.
        do {
            let (r, s) = try setup(); defer { try? FileManager.default.removeItem(at: r) }
            try Data("evil".utf8).write(to: s.activeDir.appendingPathComponent("static/js/main.js"))
            #expect(s.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest) == nil)
            #expect(!s.warmUpTrust(expectedEmbeddedTree: emb.tree, digest: digest).trusted)
        }
        // Signed object replaced by one from an unknown key.
        do {
            let (r, s) = try setup(); defer { try? FileManager.default.removeItem(at: r) }
            try ota.writeSignedObject(root: r, signer: OtaTestSigner())
            #expect(s.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest) == nil)
        }
        // Key removed from the table (rotation).
        do {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            try ota.placeSignedActive(root: r, signer: signer)
            let s = CashTreesPWABundleStore(testRootDir: r, otaKeys: [])
            #expect(s.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest) == nil)
        }
        // minShell above this shell.
        do {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            try ota.placeSignedActive(root: r, signer: signer)
            try signer.storedObject(ota.payload(minIos: 5000), ver: ota.ver, filename: ota.filename)
                .write(to: r.appendingPathComponent("ota-signed/\(ota.tree).json"))
            let s = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey], shellBuild: 114)
            #expect(s.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest) == nil)
        }
        // update.json ver claim differs from the signed ver.
        do {
            let (r, s) = try setup(); defer { try? FileManager.default.removeItem(at: r) }
            try Data("{\"ver\":\"0.53.99\",\"filename\":\"x.zip\"}".utf8).write(to: s.activeDir.appendingPathComponent("update.json"))
            #expect(s.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest) == nil)
        }
        // A record that claims a hit and a higher version gives no identity by itself.
        do {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            let s = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            try OtaBundleFixture.writeTree(s.activeDir, index: "unsigned-99", ver: "0.53.99")
            #expect(s.activeResolvedIdentity(embeddedVersion: emb.ver, embeddedTree: emb.tree, digest: digest) == nil)
        }
    }

    // MARK: Download staging and concurrency

    @Test func downloadStagingChecksContentAndRereadsTheReference() throws {
        let signer = OtaTestSigner()
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let s49 = try OtaBundleFixture.make(index: "s-49", ver: "0.53.49")
        let v = CashTreesPWAOtaVerifier(trustedKeys: [signer.publicKey], shellBuild: 999)
        let check = v.verifyManifest(signer.updateJson(s49.payload(), ver: s49.ver, filename: s49.filename), referenceVersion: "0.53.48")
        let manifest = try #require(check.manifest)
        let object = try #require(check.signedObject)
        // Normal: staged, signed object stored, update.json not rewritten.
        do {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
            #expect(try store.installDownloadToStaging(zip: s49.zip, manifest: manifest, signedObject: object) == .ok)
            #expect(FileManager.default.fileExists(atPath: r.appendingPathComponent("ota-signed/\(s49.tree).json").path))
            #expect(CashTreesPWASameVersionRule.treeDigest(at: store.stagingDir) == s49.tree)
            #expect(store.pendingUpdateVersion() == "0.53.49")
            // Apply, then the next cold start records origin=ota; the one after is fast.
            try store.promoteStagingToActive()
            let o = try CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
            #expect(o.selectedOrigin == "ota" && o.decision == "embedded-older-ignored")
            let o2 = try CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
            #expect(o2.path == .fast)
        }
        // Content mismatch: a ZIP whose tree is not the signed contentDigest.
        do {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
            let wrong = try OtaBundleFixture.make(index: "not-signed-content", ver: "0.53.49")
            #expect(try store.installDownloadToStaging(zip: wrong.zip, manifest: manifest, signedObject: object) == .contentMismatch)
            #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path))
        }
        // C1c: the active moved to an equal or higher verified version while downloading: the commit is refused.
        do {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            let e49 = try OtaBundleFixture.make(index: "emb-49", ver: "0.53.49")
            try store.coldStart(bundledZip: e49.zip, facts: e49.facts, shellBuild: "114")
            #expect(try store.installDownloadToStaging(zip: s49.zip, manifest: manifest, signedObject: object) == .downgrade)
            #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path))
        }
        // C1b: killed between "ota-signed written" and "staging renamed": an orphan signed object is harmless, and a
        // staging without a valid signed object is not a candidate.
        do {
            let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
            let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
            try s49.writeSignedObject(root: r, signer: signer)
            let o = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
            #expect(o.decision == "installed-first" && index(store) == "emb-48")
            // A foreign partial directory is residue and is removed by the full pass.
            try FileManager.default.createDirectory(at: r.appendingPathComponent(".staging-partial-OTHER"), withIntermediateDirectories: true)
            let o2 = try CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey]).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
            #expect(o2.reason == "residue")
            #expect(!FileManager.default.fileExists(atPath: r.appendingPathComponent(".staging-partial-OTHER").path))
        }
    }

    @Test func noncanonicalDownloadIsRefused() throws {
        let signer = OtaTestSigner()
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let src = try OtaBundleFixture.tempDir("nc")
        try OtaBundleFixture.writeTree(src, index: "nc", ver: "0.53.49")
        try Data("x".utf8).write(to: src.appendingPathComponent("._junk"))
        let zip = src.deletingLastPathComponent().appendingPathComponent("nc-\(UUID().uuidString).zip")
        try FileManager.default.zipItem(at: src, to: zip, shouldKeepParent: false)
        let r = try root(); defer { try? FileManager.default.removeItem(at: r) }
        let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        let m = CashTreesPWAOtaManifest(ver: "0.53.49", filename: "SilentPassUI-0.53.49.zip", sha256: "", size: 1,
                                        contentDigest: String(repeating: "0", count: 64), minShellIos: 0, minShellAndroid: 0,
                                        issuedAt: 0, keyId: signer.publicKey.keyId, payloadSha256: "")
        #expect(try store.installDownloadToStaging(zip: zip, manifest: m, signedObject: Data()) == .noncanonicalZip)
    }

    @Test func promotionRefusedWhenTheRecordCannotBeDeleted() throws {
        let r = try root()
        defer { chmod(r.path, 0o755); try? FileManager.default.removeItem(at: r) }
        let signer = OtaTestSigner()
        let emb = try OtaBundleFixture.make(index: "emb-48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: r, otaKeys: [signer.publicKey])
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        let s = try OtaBundleFixture.make(index: "s-49", ver: "0.53.49")
        try s.placeSignedStaging(root: r, signer: signer)
        #expect(chmod(r.path, 0o555) == 0)
        #expect(throws: (any Error).self) { try store.promoteStagingToActive() }
        #expect(index(store) == "emb-48")
    }
}
