//
//  CashTreesPWABootstrapTests.swift
//  CashTrees_iOSTests
//
//  Integration tests for the same-version repair (same-version repair design): bootstrap decisions,
//  no-downgrade, crash recovery, lock against concurrent bootstrap/OTA, and tree digest fixture equality.
//

import Foundation
import Testing
import ZIPFoundation
@testable import CashTrees_iOS

@Suite(.serialized)
struct CashTreesPWABootstrapTests {
    private func tempRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pwa-boot-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func writeDir(_ dir: URL, index: String, ver: String) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data(index.utf8).write(to: dir.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"\(ver)\",\"filename\":\"SilentPassUI-\(ver).zip\"}".utf8)
            .write(to: dir.appendingPathComponent("update.json"))
    }

    /// Builds a ZIP with index.html and update.json (the shape the bootstrap expects) and returns it with its tree digest.
    private func makeBundledZip(index: String, ver: String) throws -> (zip: URL, treeDigest: String) {
        let src = try tempRoot()
        try writeDir(src, index: index, ver: ver)
        let zip = src.deletingLastPathComponent().appendingPathComponent("SilentPassUI-\(UUID().uuidString).zip")
        try FileManager.default.zipItem(at: src, to: zip, shouldKeepParent: false)
        // The digest the build would record: computed over the unzipped content.
        let unzipped = try tempRoot()
        try FileManager.default.unzipItem(at: zip, to: unzipped)
        let digest = CashTreesPWASameVersionRule.treeDigest(at: unzipped) ?? ""
        return (zip, digest)
    }

    private func activeIndex(_ store: CashTreesPWABundleStore) -> String? {
        try? String(contentsOf: store.activeDir.appendingPathComponent("index.html"), encoding: .utf8)
    }

    @Test func sameVersionNoRecordDifferentTreeReinstallsAndWritesProvenance() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeDir(store.activeDir, index: "legacy-83cdd99", ver: "0.53.42")
        let (zip, tree) = try makeBundledZip(index: "embedded-9367a56b", ver: "0.53.42")
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: tree, embeddedZipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip))
        #expect(activeIndex(store) == "embedded-9367a56b")
        let record = try JSONDecoder().decode(
            CashTreesPWASourceRecord.self,
            from: Data(contentsOf: store.activeDir.appendingPathComponent(".source.json"))
        )
        #expect(record.source == .bundled)
        #expect(record.zipSha256 == CashTreesPWASameVersionRule.fileSHA256(at: zip))
    }

    @Test func sameVersionSameTreeIsKeptWithoutUnpacking() throws {
        // an active equal to the embedded tree is kept as it is; the ZIP is not unpacked.
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeDir(store.activeDir, index: "same", ver: "0.53.42")
        let (zip, tree) = try makeBundledZip(index: "same", ver: "0.53.42")
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: tree, embeddedZipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip))
        #expect(activeIndex(store) == "same")
        #expect(store.lastColdStart.decision == "kept-identical")
        #expect(store.lastColdStart.unpackCount == 0)
        #expect(store.lastColdStart.zipReadCount == 0)
    }

    @Test func recordedStartIsNotRecomputedOnNextBoot() throws {
        // once the completion record is written, later starts take the fast path: no digest, no unpack.
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeDir(store.activeDir, index: "same", ver: "0.53.42")
        let (zip, tree) = try makeBundledZip(index: "same", ver: "0.53.42")
        let facts = CashTreesPWAEmbeddedFacts(ver: "0.53.42", zipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip), treeDigest: tree)
        try store.coldStart(bundledZip: zip, facts: facts, shellBuild: "113")
        let afterRecord = store.activeTreeDigestComputations
        try store.coldStart(bundledZip: zip, facts: facts, shellBuild: "113")
        try store.coldStart(bundledZip: zip, facts: facts, shellBuild: "113")
        #expect(store.lastColdStart.path == .fast)
        #expect(store.activeTreeDigestComputations == afterRecord)
    }

    @Test func higherVersionUnverifiedActiveIsRepairedUnderTheShippedPolicy() throws {
        // A higher-version active this shell cannot verify (an OTA tree) has no
        // bridge trust, so the cold start repairs it with the embedded build.
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeDir(store.activeDir, index: "higher-ota", ver: "0.53.43")
        let (zip, tree) = try makeBundledZip(index: "embedded", ver: "0.53.42")
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: tree, embeddedZipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip))
        #expect(activeIndex(store) == "embedded")
        #expect(store.lastColdStart.decision == "repaired-unverifiable")
    }

    @Test func noEmbeddedManifestKeepsSameVersionActiveUnchanged() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeDir(store.activeDir, index: "legacy", ver: "0.53.42")
        let (zip, _) = try makeBundledZip(index: "embedded", ver: "0.53.42")
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: nil, embeddedZipSha256: nil)
        #expect(activeIndex(store) == "legacy")
    }

    @Test func crashAfterMoveAsideRestoresPreviousActive() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        // Simulated kill between "active -> active.prev" and "bundled -> active": only active.prev exists.
        try writeDir(root.appendingPathComponent("active.prev", isDirectory: true), index: "interrupted", ver: "0.53.42")
        store.recoverInterruptedSwap()
        #expect(activeIndex(store) == "interrupted")
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("active.prev").path))
    }

    @Test func crashAfterInstallDropsStalePrevAndKeepsActive() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        // Simulated kill after the new active is in place but before active.prev is removed.
        try writeDir(store.activeDir, index: "new-active", ver: "0.53.42")
        try writeDir(root.appendingPathComponent("active.prev", isDirectory: true), index: "stale", ver: "0.53.41")
        store.recoverInterruptedSwap()
        #expect(activeIndex(store) == "new-active")
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("active.prev").path))
    }

    @Test func concurrentBootstrapCallsLeaveAValidActive() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        let (zip, tree) = try makeBundledZip(index: "embedded", ver: "0.53.42")
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            try? store.bootstrap(bundledZip: zip, embeddedTreeDigest: tree, embeddedZipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip))
        }
        #expect(activeIndex(store) == "embedded")
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("active.prev").path))
    }

    @Test func bootstrapAndOtaPromotionShareTheLock() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        let (zip, tree) = try makeBundledZip(index: "embedded", ver: "0.53.42")
        try writeDir(store.activeDir, index: "legacy", ver: "0.53.41")
        DispatchQueue.concurrentPerform(iterations: 6) { i in
            if i % 2 == 0 {
                try? store.bootstrap(bundledZip: zip, embeddedTreeDigest: tree, embeddedZipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip))
            } else {
                let staging = root.appendingPathComponent("staging", isDirectory: true)
                try? FileManager.default.removeItem(at: staging)
                try? writeDir(staging, index: "ota-0.53.43", ver: "0.53.43")
                try? store.promoteStagingToActive()
            }
        }
        // Whatever the interleaving, the active directory is complete (never half-swapped).
        #expect(FileManager.default.fileExists(atPath: store.activeDir.appendingPathComponent("index.html").path))
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("active.prev").path))
    }

    @Test func treeDigestMatchesBuildFixture() throws {
        // Fixture: the same layout the build script digests (scripts/pwa-tree-digest.sh), with the expected value
        // produced by that independent shell implementation. Equal values prove build-time and runtime agree.
        let dir = try tempRoot(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data("<html>fixture</html>".utf8).write(to: dir.appendingPathComponent("index.html"))
        try FileManager.default.createDirectory(at: dir.appendingPathComponent("static/js"), withIntermediateDirectories: true)
        try Data("console.log('a')".utf8).write(to: dir.appendingPathComponent("static/js/a.js"))
        try Data("body{}".utf8).write(to: dir.appendingPathComponent("static/main.css"))
        try Data("{\"ver\":\"0.53.42\"}".utf8).write(to: dir.appendingPathComponent("update.json"))
        try Data("junk".utf8).write(to: dir.appendingPathComponent(".DS_Store"))
        #expect(CashTreesPWASameVersionRule.treeDigest(at: dir) == "2c5bd285d3397d911f5124d4816ee1b608e2c9bff155fc66c165446f46ffde3b")
    }

    @Test func bootstrapTimingIsRecorded() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        let blob = String(repeating: "a", count: 180_000)
        let src = try tempRoot()
        try writeDir(src, index: "x", ver: "0.53.42")
        for i in 0..<100 { try Data(blob.utf8).write(to: src.appendingPathComponent("chunk\(i).js")) }
        let zip = src.deletingLastPathComponent().appendingPathComponent("timing-\(UUID().uuidString).zip")
        try FileManager.default.zipItem(at: src, to: zip, shouldKeepParent: false)
        try writeDir(store.activeDir, index: "legacy", ver: "0.53.42")
        let start = Date()
        let unz = try tempRoot(); try FileManager.default.unzipItem(at: zip, to: unz)
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: CashTreesPWASameVersionRule.treeDigest(at: unz),
                            embeddedZipSha256: CashTreesPWASameVersionRule.fileSHA256(at: zip))
        #expect(store.lastColdStart.unpackCount == 1)
        let elapsed = Date().timeIntervalSince(start)
        print("[PWA-TIMING] bootstrap same-version reinstall (~18 MB): \(String(format: "%.3f", elapsed)) s")
        #expect(elapsed < 5.0)
    }
}
