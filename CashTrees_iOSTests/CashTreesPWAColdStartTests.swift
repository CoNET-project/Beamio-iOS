//
//  CashTreesPWAColdStartTests.swift
//  CashTrees_iOSTests
//
//  Cold-start completion record: fast path purity, full-pass decisions,
//  fingerprint sensitivity, record corruption, delete-before-change, staging and promotion recovery, strict promotion, strict version
//  parsing, bridge independence and record location.
//

import Darwin
import Foundation
import Testing
import ZIPFoundation
@testable import CashTrees_iOS

@Suite(.serialized)
struct CashTreesPWAColdStartTests {
    struct Fixture {
        let zip: URL
        let facts: CashTreesPWAEmbeddedFacts
    }

    private func tempRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pwa-cold-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func writeDir(_ dir: URL, index: String, ver: String) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data(index.utf8).write(to: dir.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"\(ver)\",\"filename\":\"SilentPassUI-\(ver).zip\"}".utf8)
            .write(to: dir.appendingPathComponent("update.json"))
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("static/js"), withIntermediateDirectories: true)
        try Data("console.log('\(index)')".utf8).write(to: dir.appendingPathComponent("static/js/main.js"))
    }

    /// An embedded build: a ZIP and the build identity a real build would record for it.
    private func makeEmbedded(index: String, ver: String) throws -> Fixture {
        let src = try tempRoot()
        try writeDir(src, index: index, ver: ver)
        let zip = src.deletingLastPathComponent().appendingPathComponent("emb-\(UUID().uuidString).zip")
        try FileManager.default.zipItem(at: src, to: zip, shouldKeepParent: false)
        let unzipped = try tempRoot()
        try FileManager.default.unzipItem(at: zip, to: unzipped)
        let facts = CashTreesPWAEmbeddedFacts(
            ver: ver,
            zipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip),
            treeDigest: CashTreesPWASameVersionRule.treeDigest(at: unzipped)
        )
        return Fixture(zip: zip, facts: facts)
    }

    private func index(_ store: CashTreesPWABundleStore) -> String? {
        try? String(contentsOf: store.activeDir.appendingPathComponent("index.html"), encoding: .utf8)
    }

    /// A forged v2 record for this root (the install id is the real one, so only the claims are false).
    private func forgedRecord(root: URL, emb: Fixture, tree: String, ver: String, fingerprint: String) -> CashTreesPWAColdStartRecord {
        CashTreesPWAColdStartRecord(
            schema: CashTreesPWAColdStartRecord.schemaV2, ruleVersion: CashTreesPWAColdStartRecord.ruleVersion,
            platform: "ios", variant: "ios", installId: CashTreesPWAInstallIdentity.currentOrCreate(root: root) ?? "",
            shellBuild: "113",
            embedded: .init(zipSha256: emb.facts.zipSha256 ?? "", contentDigest: tree, ver: "0.53.48", outcome: "identical"),
            selected: .init(origin: "embedded", contentDigest: tree, ver: ver, ota: nil, generation: 9),
            network: "n/a", activeFingerprint: fingerprint, decision: "kept-identical", result: "complete",
            completedAtUtc: "2026-11-24T00:00:00Z")
    }

    private func recordData(_ root: URL) -> Data? {
        try? Data(contentsOf: CashTreesPWAColdStartRecordIO.recordURL(root: root))
    }

    // 1. First install, then a fast second start in a new store instance (a process restart).
    @Test func firstInstallThenFastPathWithZeroUnpackCompareZipReadAndDigest() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let first = CashTreesPWABundleStore(testRootDir: root)
        let o1 = try first.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o1.path == .full)
        #expect(o1.decision == "installed-first")
        #expect(o1.unpackCount == 1)
        #expect(o1.recordWritten)
        let bytes = recordData(root)
        #expect(bytes != nil)

        let digestsBefore = CashTreesPWASameVersionRule.treeDigestComputeCount
        let comparesBefore = CashTreesPWAVersion.compareCount
        let second = CashTreesPWABundleStore(testRootDir: root)
        let o2 = try second.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o2.path == .fast, "reason=\(o2.reason)")
        #expect(o2.unpackCount == 0)
        #expect(o2.versionCompareCount == 0)
        #expect(o2.zipReadCount == 0)
        #expect(o2.fullDigestCount == 0)
        #expect(CashTreesPWASameVersionRule.treeDigestComputeCount == digestsBefore)
        #expect(CashTreesPWAVersion.compareCount == comparesBefore)
        #expect(recordData(root) == bytes)
        #expect(index(second) == "e48")
        print("[COLDSTART-TEST] first: \(o1.logLine)")
        print("[COLDSTART-TEST] reuse: \(o2.logLine)")
    }

    // 2. No record, same identical active (an upgrade from a shell without records): full, no unpack, record written.
    @Test func noRecordIdenticalActiveKeepsWithoutUnpackThenFast() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "same", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: root)
        try FileManager.default.unzipItem(at: emb.zip, to: store.activeDir)
        let o1 = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o1.path == .full)
        #expect(o1.reason == "no-record")
        #expect(o1.decision == "kept-identical")
        #expect(o1.unpackCount == 0)
        #expect(o1.zipReadCount == 0)
        #expect(o1.recordWritten)
        let o2 = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o2.path == .fast)
    }

    // 3. Embedded update (new ZIP, version and build): the previous embedded tree is no longer verifiable by the new
    // shell, so the new embedded build is installed as a repair; next start fast.
    @Test func newerEmbeddedBuildInstallsThenFast() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let old = try makeEmbedded(index: "e47", ver: "0.53.47")
        let new = try makeEmbedded(index: "e48", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: old.zip, facts: old.facts, shellBuild: "111")
        let store = CashTreesPWABundleStore(testRootDir: root)
        let o = try store.coldStart(bundledZip: new.zip, facts: new.facts, shellBuild: "113")
        #expect(o.path == .full)
        #expect(o.reason == "zip-changed")
        #expect(o.decision == "repaired-unverifiable")
        #expect(o.unpackCount == 1)
        #expect(o.versionCompareCount == 0)
        #expect(index(store) == "e48")
        let o2 = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: new.zip, facts: new.facts, shellBuild: "113")
        #expect(o2.path == .fast)
    }

    // 4. Same version, different bytes, same build number (QA): the ZIP identity changed, so the record misses; repair.
    @Test func sameVersionDifferentBytesSameBuildRepairs() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let a = try makeEmbedded(index: "qa-a", ver: "0.53.48")
        let b = try makeEmbedded(index: "qa-b", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: a.zip, facts: a.facts, shellBuild: "113")
        let store = CashTreesPWABundleStore(testRootDir: root)
        let o = try store.coldStart(bundledZip: b.zip, facts: b.facts, shellBuild: "113")
        #expect(o.reason == "zip-changed")
        #expect(o.decision == "repaired-unverifiable")
        #expect(index(store) == "qa-b")
    }

    // 5. Older embedded over a local the new shell cannot verify (the previous embedded build): only the new embedded
    // build is a verified candidate, so it is installed (an older embedded only stays out when the local is verified).
    @Test func olderEmbeddedOverAnUnverifiableLocalIsInstalled() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let newer = try makeEmbedded(index: "e48", ver: "0.53.48")
        let older = try makeEmbedded(index: "e47", ver: "0.53.47")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: newer.zip, facts: newer.facts, shellBuild: "113")
        let store = CashTreesPWABundleStore(testRootDir: root)
        let r = try store.coldStart(bundledZip: older.zip, facts: older.facts, shellBuild: "114")
        #expect(r.decision == "repaired-unverifiable")
        #expect(index(store) == "e47")
    }

    // 6. Fingerprint sensitivity: same-size rewrite with mtime restored still changes (ctime); delete/add/replace change.
    @Test func fingerprintDetectsSameSizeRewriteDeleteAddAndReplace() throws {
        let dir = try tempRoot(); defer { try? FileManager.default.removeItem(at: dir) }
        try writeDir(dir, index: "abcd", ver: "0.53.48")
        let file = dir.appendingPathComponent("index.html")
        let base = CashTreesPWAFingerprint.of(dir)
        #expect(base != nil)
        var st = stat()
        #expect(lstat(file.path, &st) == 0)
        let savedMtime = st.st_mtimespec
        Thread.sleep(forTimeInterval: 0.01)
        try Data("wxyz".utf8).write(to: file) // same size
        var times = [timespec(tv_sec: st.st_atimespec.tv_sec, tv_nsec: st.st_atimespec.tv_nsec), savedMtime]
        #expect(utimensat(AT_FDCWD, file.path, &times, 0) == 0)
        var after = stat()
        #expect(lstat(file.path, &after) == 0)
        #expect(after.st_mtimespec.tv_sec == savedMtime.tv_sec && after.st_mtimespec.tv_nsec == savedMtime.tv_nsec)
        let rewritten = CashTreesPWAFingerprint.of(dir)
        #expect(rewritten != base, "same-size rewrite with restored mtime must change the fingerprint")

        try Data("x".utf8).write(to: dir.appendingPathComponent("extra.js"))
        let added = CashTreesPWAFingerprint.of(dir)
        #expect(added != rewritten)
        try FileManager.default.removeItem(at: dir.appendingPathComponent("extra.js"))
        #expect(CashTreesPWAFingerprint.of(dir) != added)
        let js = dir.appendingPathComponent("static/js/main.js")
        let before = CashTreesPWAFingerprint.of(dir)
        let tmp = dir.appendingPathComponent("static/js/.tmp")
        try Data("console.log('abcd')".utf8).write(to: tmp)
        #expect(rename(tmp.path, js.path) == 0) // replace with identical bytes: inode changes
        #expect(CashTreesPWAFingerprint.of(dir) != before)
        // Marker files are excluded; a symbolic link makes it unknown.
        let marked = CashTreesPWAFingerprint.of(dir)
        try Data("{}".utf8).write(to: dir.appendingPathComponent(".source.json"))
        #expect(CashTreesPWAFingerprint.of(dir) == marked)
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("link"), withDestinationURL: file)
        #expect(CashTreesPWAFingerprint.of(dir) == nil)
    }

    // 7. Corrupt record: truncated JSON, unknown schema, tmp residue, empty identity field -> full pass and rewrite.
    @Test func corruptRecordTakesTheFullPassAndRewrites() throws {
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let corruptions: [(String, (URL) throws -> Void)] = [
            ("truncated", { root in
                let url = CashTreesPWAColdStartRecordIO.recordURL(root: root)
                let data = try Data(contentsOf: url)
                try data.prefix(data.count / 2).write(to: url)
            }),
            ("schema", { root in
                let url = CashTreesPWAColdStartRecordIO.recordURL(root: root)
                let text = try String(contentsOf: url, encoding: .utf8).replacingOccurrences(of: "beamio.pwa.coldstart.v2", with: "beamio.pwa.coldstart.v9")
                try Data(text.utf8).write(to: url)
            }),
            ("tmp", { root in
                try Data("{partial".utf8).write(to: CashTreesPWAColdStartRecordIO.tmpURL(root: root))
            }),
            ("empty", { root in
                let url = CashTreesPWAColdStartRecordIO.recordURL(root: root)
                let rec = try JSONDecoder().decode(CashTreesPWAColdStartRecord.self, from: Data(contentsOf: url))
                let broken = CashTreesPWAColdStartRecord(
                    schema: rec.schema, ruleVersion: rec.ruleVersion, platform: rec.platform, variant: rec.variant,
                    installId: rec.installId, shellBuild: rec.shellBuild,
                    embedded: .init(zipSha256: "", contentDigest: rec.embedded.contentDigest, ver: rec.embedded.ver,
                                    outcome: rec.embedded.outcome),
                    selected: rec.selected, network: rec.network, activeFingerprint: rec.activeFingerprint,
                    decision: rec.decision, result: rec.result, completedAtUtc: rec.completedAtUtc)
                try JSONEncoder().encode(broken).write(to: url)
            }),
        ]
        for (name, corrupt) in corruptions {
            let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
            try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
            try corrupt(root)
            let o = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
            #expect(o.path == .full, "\(name)")
            #expect(o.unpackCount == 0, "\(name): identical active needs no unpack")
            #expect(o.recordWritten, "\(name)")
            #expect(!FileManager.default.fileExists(atPath: CashTreesPWAColdStartRecordIO.tmpURL(root: root).path), "\(name)")
            let again = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
            #expect(again.path == .fast, "\(name)")
        }
    }

    // 8. Delete-before-change: a kill mid-swap leaves no record; the next start recovers, takes the full pass, rewrites.
    @Test func interruptedSwapNeverLeavesARecordWithAHalfActive() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let old = try makeEmbedded(index: "e47", ver: "0.53.47")
        let new = try makeEmbedded(index: "e48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: root)
        try store.coldStart(bundledZip: old.zip, facts: old.facts, shellBuild: "111")
        // Simulate the new build's start killed after "record deleted, active -> active.prev" and before "bundled -> active".
        CashTreesPWAColdStartRecordIO.invalidate(root: root)
        try FileManager.default.moveItem(at: store.activeDir, to: root.appendingPathComponent("active.prev"))
        try FileManager.default.createDirectory(at: root.appendingPathComponent("bundled"), withIntermediateDirectories: true)
        #expect(recordData(root) == nil)
        let next = CashTreesPWABundleStore(testRootDir: root)
        let o = try next.coldStart(bundledZip: new.zip, facts: new.facts, shellBuild: "113")
        #expect(o.path == .full)
        #expect(o.reason == "no-record")
        #expect(o.decision == "repaired-unverifiable")
        #expect(index(next) == "e48")
        #expect(o.recordWritten)
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("active.prev").path))
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("bundled").path))
    }

    // 9. OTA promotion killed between "active -> backup" and "staging -> active": the backup is restored.
    @Test func interruptedPromotionRestoresTheBackup() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: root)
        try FileManager.default.unzipItem(at: emb.zip, to: store.backupDir)
        #expect(!FileManager.default.fileExists(atPath: store.activeDir.path))
        let o = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o.decision == "kept-identical", "the restored backup is the embedded tree")
        #expect(o.unpackCount == 0)
        #expect(index(store) == "e48")
    }

    // 10. Staging without a valid signed identity is removed in the full pass; the fast path never reads staging.
    @Test func stagingIsReconciledOnlyInTheFullPass() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeDir(store.stagingDir, index: "unsigned-ota", ver: "0.53.49")
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path), "an unsigned staging never stays")
        // A staging written after the record exists is left alone by the fast path, with zero comparisons.
        try writeDir(store.stagingDir, index: "later", ver: "0.53.49")
        let second = CashTreesPWABundleStore(testRootDir: root)
        let o = try second.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o.path == .fast)
        #expect(o.versionCompareCount == 0)
        #expect(FileManager.default.fileExists(atPath: store.stagingDir.path))
    }

    // 11. Promotion: signed and strictly newer only; the record is deleted before the active directory moves.
    @Test func promotionIsSignedStrictAndDeletesTheRecordFirst() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let signer = OtaTestSigner()
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: root, otaKeys: [signer.publicKey])
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        // Unsigned newer staging: refused.
        try writeDir(store.stagingDir, index: "unsigned", ver: "0.53.49")
        #expect(throws: (any Error).self) { try store.promoteStagingToActive() }
        #expect(recordData(root) != nil)
        // Signed same version: refused.
        let same = try OtaBundleFixture.make(index: "same-ota", ver: "0.53.48")
        try same.placeSignedStaging(root: root, signer: signer)
        #expect(throws: (any Error).self) { try store.promoteStagingToActive() }
        #expect(recordData(root) != nil)
        #expect(index(store) == "e48")
        // Signed newer: promoted, record deleted first.
        let newer = try OtaBundleFixture.make(index: "ota-49", ver: "0.53.49")
        try newer.placeSignedStaging(root: root, signer: signer)
        try store.promoteStagingToActive()
        #expect(recordData(root) == nil)
        #expect(index(store) == "ota-49")
    }

    // 12. Strict version parsing.
    @Test func strictVersionParsing() {
        #expect(CashTreesPWAVersion.parse("0.53.48") == [0, 53, 48])
        #expect(CashTreesPWAVersion.parse("0.0.0") == [0, 0, 0])
        for bad in ["0.53.48-rc", "v0.53.48", "0.53", "0.53.48.1", "01.2.3", "1.02.3", "1234567890.0.0", "", "0.53.48+x", "a.b.c", "0..1", " 0.53.48"] {
            #expect(CashTreesPWAVersion.parse(bad) == nil, "\(bad)")
        }
        #expect(CashTreesPWAVersion.isStrictlyNewer(old: "0.52.9", new: "0.52.10") == true)
        #expect(CashTreesPWAVersion.isStrictlyNewer(old: "0.53.48", new: "0.53.48") == false)
        #expect(CashTreesPWAVersion.isStrictlyNewer(old: "0.53.48", new: "0.53.47") == false)
        #expect(CashTreesPWAVersion.isStrictlyNewer(old: "0.53.48", new: "0.53.49-rc") == nil)
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.53.48", newVer: "0.53.49-rc") == false)
    }

    // 13. Bridge independence: a record never grants trust; a tampered active after a fast hit fails the gate,
    // and the warm-up deletes the record. A forged record pointing at a tampered tree gets no trust either.
    @Test func recordNeverGrantsBridgeTrust() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let tree = emb.facts.treeDigest ?? ""
        let digest: (URL) -> String? = { CashTreesPWASameVersionRule.treeDigest(at: $0) }
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        let store = CashTreesPWABundleStore(testRootDir: root)
        #expect(try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113").path == .fast)
        #expect(store.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: tree, digest: digest))
        // Tamper after the fast hit.
        try Data("console.log('evil')".utf8).write(to: store.activeDir.appendingPathComponent("static/js/main.js"))
        #expect(!store.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: tree, digest: digest))
        store.warmUpTrustDigest(expectedTreeSHA256: tree, digest: digest)
        #expect(recordData(root) == nil)

        // Forge a record whose fingerprint matches the tampered tree and whose digests claim the embedded build.
        let fp = CashTreesPWAFingerprint.of(store.activeDir) ?? ""
        let forged = forgedRecord(root: root, emb: emb, tree: tree, ver: "0.53.48", fingerprint: fp)
        #expect(CashTreesPWAColdStartRecordIO.write(forged, root: root))
        let fresh = CashTreesPWABundleStore(testRootDir: root)
        let o = try fresh.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o.path == .fast, "the forged record opens the bundle, but grants nothing")
        #expect(!fresh.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: tree, digest: digest))
        #expect(fresh.warmUpTrustDigest(expectedTreeSHA256: tree, digest: digest) != tree)
        #expect(recordData(root) == nil)
        // The next start repairs.
        let repaired = CashTreesPWABundleStore(testRootDir: root)
        let r = try repaired.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(r.decision == "repaired-unverifiable")
        #expect(repaired.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: tree, digest: digest))
    }

    // Digest cache: first check in a process is a full digest; an unchanged fingerprint reuses it.
    @Test func trustDigestIsComputedOncePerFingerprint() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        let store = CashTreesPWABundleStore(testRootDir: root)
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        let digest: (URL) -> String? = { CashTreesPWASameVersionRule.treeDigest(at: $0) }
        #expect(store.trustDigestComputations == 0)
        _ = store.activeTreeSHA256(digest: digest)
        _ = store.activeTreeSHA256(digest: digest)
        _ = store.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: emb.facts.treeDigest ?? "", digest: digest)
        #expect(store.trustDigestComputations == 1)
    }

    // The embedded ZIP cannot be used. A complete active is kept without a record; with no active the start fails.
    @Test func unusableEmbeddedZipKeepsAnActiveOrFails() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let good = try makeEmbedded(index: "e47", ver: "0.53.47")
        let next = try makeEmbedded(index: "e48", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: good.zip, facts: good.facts, shellBuild: "111")
        let badFacts = CashTreesPWAEmbeddedFacts(ver: "0.53.48", zipSha256: String(repeating: "0", count: 64), treeDigest: next.facts.treeDigest)
        let store = CashTreesPWABundleStore(testRootDir: root)
        let o = try store.coldStart(bundledZip: next.zip, facts: badFacts, shellBuild: "113")
        #expect(o.decision == "no-trusted-candidate")
        #expect(!o.recordWritten)
        #expect(index(store) == "e47")
        let empty = try tempRoot(); defer { try? FileManager.default.removeItem(at: empty) }
        #expect(throws: (any Error).self) {
            try CashTreesPWABundleStore(testRootDir: empty).coldStart(bundledZip: next.zip, facts: badFacts, shellBuild: "113")
        }
    }

    // 17. Record location: only the root record is read; a same-named file inside the active tree is ignored.
    @Test func recordIsOnlyReadFromTheRoot() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: root)
        try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        let rootRecord = try #require(recordData(root))
        CashTreesPWAColdStartRecordIO.invalidate(root: root)
        try rootRecord.write(to: store.activeDir.appendingPathComponent(CashTreesPWAColdStartRecord.fileName))
        let o = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o.path == .full)
        #expect(o.reason == "no-record")
        #expect(CashTreesPWAColdStartRecordIO.recordURL(root: root).deletingLastPathComponent().standardizedFileURL == root.standardizedFileURL)
    }

    // Record v2: an install-over with a new build number but the same ZIP reuses the record (shellBuild is log only).
    @Test func shellBuildChangeAloneStillHits() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "112")
        let o = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "114")
        #expect(o.path == .fast)
        #expect(o.unpackCount == 0 && o.versionCompareCount == 0 && o.zipReadCount == 0)
    }

    // a restore or device migration changes every inode (and ctime). That must only force a recompute:
    // full pass, identical tree kept, no unpack, record rewritten; never a refusal.
    @Test func restoredCopyWithNewInodesRecomputesWithoutRefusal() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        let store = CashTreesPWABundleStore(testRootDir: root)
        let before = CashTreesPWAFingerprint.of(store.activeDir)
        // Simulated restore: same bytes, new files (new inodes).
        let copy = root.appendingPathComponent("restored", isDirectory: true)
        try FileManager.default.copyItem(at: store.activeDir, to: copy)
        try FileManager.default.removeItem(at: store.activeDir)
        try FileManager.default.moveItem(at: copy, to: store.activeDir)
        #expect(CashTreesPWAFingerprint.of(store.activeDir) != before)
        let o = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o.path == .full)
        #expect(o.reason == "fingerprint-changed")
        #expect(o.decision == "kept-identical")
        #expect(o.unpackCount == 0)
        #expect(o.recordWritten)
        #expect(store.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: emb.facts.treeDigest ?? "",
                                          digest: { CashTreesPWASameVersionRule.treeDigest(at: $0) }))
        #expect(try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113").path == .fast)
    }

    // a forged "hit" record over a HIGHER-version active gets neither trust nor a skipped repair later.
    @Test func forgedHitRecordOverAHigherVersionActiveGetsNoTrust() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let tree = emb.facts.treeDigest ?? ""
        let digest: (URL) -> String? = { CashTreesPWASameVersionRule.treeDigest(at: $0) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeDir(store.activeDir, index: "ota-49", ver: "0.53.49")
        let forged = forgedRecord(root: root, emb: emb, tree: tree, ver: "0.53.49",
                                  fingerprint: CashTreesPWAFingerprint.of(store.activeDir) ?? "")
        #expect(CashTreesPWAColdStartRecordIO.write(forged, root: root))
        let o = try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o.path == .fast)
        #expect(!store.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: tree, digest: digest))
        #expect(!store.activeBundleMatches(expectedVersion: "0.53.49", expectedTreeSHA256: tree, digest: digest))
        #expect(store.warmUpTrustDigest(expectedTreeSHA256: tree, digest: digest) != tree)
        #expect(recordData(root) == nil)
        let r = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(r.decision == "repaired-unverifiable")
    }

    // A special file (FIFO) in the active tree makes the fingerprint unknown: the fast path misses.
    @Test func specialFileMakesTheFingerprintUnknown() throws {
        let dir = try tempRoot(); defer { try? FileManager.default.removeItem(at: dir) }
        try writeDir(dir, index: "abcd", ver: "0.53.48")
        #expect(CashTreesPWAFingerprint.of(dir) != nil)
        #expect(mkfifo(dir.appendingPathComponent("static/pipe").path, 0o600) == 0)
        #expect(CashTreesPWAFingerprint.of(dir) == nil)
    }

    // Bridge wait: a gate check that arrives while the background warm-up holds the store lock waits for it (no timeout,
    // bounded by one full digest) and then reuses the warm-up result; it never answers from the record or the fingerprint.
    @Test func gateCheckDuringWarmUpWaitsAndReusesTheResult() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        let tree = emb.facts.treeDigest ?? ""
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        let store = CashTreesPWABundleStore(testRootDir: root)
        #expect(try store.coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113").path == .fast)
        let started = DispatchSemaphore(value: 0)
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            store.warmUpTrustDigest(expectedTreeSHA256: tree) { url in
                started.signal()
                Thread.sleep(forTimeInterval: 0.4)
                return CashTreesPWASameVersionRule.treeDigest(at: url)
            }
            done.signal()
        }
        started.wait()
        let t0 = Date()
        let ok = store.activeBundleMatches(expectedVersion: "0.53.48", expectedTreeSHA256: tree) { _ in
            Issue.record("the gate recomputed instead of reusing the warm-up digest")
            return nil
        }
        let waited = Date().timeIntervalSince(t0)
        done.wait()
        #expect(ok)
        #expect(waited >= 0.3, "waited \(waited)")
        #expect(store.trustDigestComputations == 1)
        print("[COLDSTART-TEST] gate waited \(Int(waited * 1000)) ms for the warm-up digest")
    }

    @Test func startErrorCopyInThreeLanguages() {
        let zh = CashTreesStartErrorCopy.forLanguages(["zh-Hans-CN"], kind: .contentCheckFailed)
        let ja = CashTreesStartErrorCopy.forLanguages(["ja-JP"], kind: .contentCheckFailed)
        let en = CashTreesStartErrorCopy.forLanguages(["en-US"], kind: .contentCheckFailed)
        #expect(zh.retry == "重试")
        #expect(ja.retry == "再試行")
        #expect(en.retry == "Try again")
        #expect(CashTreesStartErrorCopy.forLanguages(["fr-FR"], kind: .startFailed).title == "Beamio couldn't start")
        for c in [zh, ja, en] { print("[COLDSTART-COPY] \(c.title) | \(c.body) | \(c.retry)") }
    }

    // A stale unpack target left by an interrupted start is cleared by the full pass, so the next start is fast.
    @Test func staleBundledResidueIsClearedSoTheNextStartIsFast() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let emb = try makeEmbedded(index: "e48", ver: "0.53.48")
        try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("bundled"), withIntermediateDirectories: true)
        let o1 = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o1.reason == "residue")
        #expect(o1.unpackCount == 0)
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("bundled").path))
        let o2 = try CashTreesPWABundleStore(testRootDir: root).coldStart(bundledZip: emb.zip, facts: emb.facts, shellBuild: "113")
        #expect(o2.path == .fast)
        #expect(o2.elapsedMs >= 0)
    }

    // Delete-before-change: when the record cannot be deleted, neither the cold start nor a promotion changes the active.
    @Test func undeletableRecordBlocksAnyChangeToTheActive() throws {
        let root = try tempRoot()
        defer {
            chmod(root.path, 0o755)
            try? FileManager.default.removeItem(at: root)
        }
        let old = try makeEmbedded(index: "e47", ver: "0.53.47")
        let new = try makeEmbedded(index: "e48", ver: "0.53.48")
        let store = CashTreesPWABundleStore(testRootDir: root)
        try store.coldStart(bundledZip: old.zip, facts: old.facts, shellBuild: "111")
        try writeDir(store.stagingDir, index: "ota-49", ver: "0.53.49")
        #expect(chmod(root.path, 0o555) == 0)
        let o = try store.coldStart(bundledZip: new.zip, facts: new.facts, shellBuild: "113")
        #expect(o.decision == "record-not-deleted")
        #expect(o.unpackCount == 0)
        #expect(index(store) == "e47")
        #expect(throws: (any Error).self) { try store.promoteStagingToActive() }
        #expect(index(store) == "e47")
        #expect(chmod(root.path, 0o755) == 0)
        let fixed = try store.coldStart(bundledZip: new.zip, facts: new.facts, shellBuild: "113")
        #expect(fixed.decision == "repaired-unverifiable")
    }
}
