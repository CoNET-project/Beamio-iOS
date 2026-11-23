//
//  CashTreesPWASameVersionRuleTests.swift
//  CashTrees_iOSTests
//
//  Same-version repair design: same-version repair rule, provenance record, tree digest.
//

import Foundation
import Testing
@testable import CashTrees_iOS

@Suite(.serialized)
struct CashTreesPWASameVersionRuleTests {
    private func makeTree(_ files: [String: String]) throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("pwa-tree-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        for (rel, content) in files {
            let url = root.appendingPathComponent(rel)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data(content.utf8).write(to: url)
        }
        return root
    }

    @Test func treeDigestIsStableAndIgnoresExcludedFiles() throws {
        let a = try makeTree(["index.html": "<html>", "static/js/main.js": "x"])
        let b = try makeTree(["index.html": "<html>", "static/js/main.js": "x"])
        #expect(CashTreesPWASameVersionRule.treeDigest(at: a) == CashTreesPWASameVersionRule.treeDigest(at: b))
        // Excluded names must not change the digest: .source.json, ._* and any-level __MACOSX only.
        try Data("junk".utf8).write(to: a.appendingPathComponent("._index.html"))
        try Data("{}".utf8).write(to: a.appendingPathComponent(".source.json"))
        try FileManager.default.createDirectory(at: a.appendingPathComponent("__MACOSX"), withIntermediateDirectories: true)
        try Data("junk".utf8).write(to: a.appendingPathComponent("__MACOSX/x"))
        #expect(CashTreesPWASameVersionRule.treeDigest(at: a) == CashTreesPWASameVersionRule.treeDigest(at: b))
    }

    @Test func dsStoreIsNotExcludedFromTheDigest() throws {
        let a = try makeTree(["index.html": "<html>"])
        let before = CashTreesPWASameVersionRule.treeDigest(at: a)
        try Data("junk".utf8).write(to: a.appendingPathComponent(".DS_Store"))
        #expect(CashTreesPWASameVersionRule.treeDigest(at: a) != before)
    }

    @Test func treeDigestChangesWhenContentChanges() throws {
        let a = try makeTree(["index.html": "<html>", "static/js/main.js": "x"])
        let b = try makeTree(["index.html": "<html>", "static/js/main.js": "y"])
        #expect(CashTreesPWASameVersionRule.treeDigest(at: a) != CashTreesPWASameVersionRule.treeDigest(at: b))
    }

    @Test func treeDigestMatchesNestedMacosxFixture() throws {
        // Same fixture as scripts/pwa-tree-digest.sh: __MACOSX is excluded at any level, in both implementations.
        let dir = try makeTree([
            "index.html": "<html>",
            "update.json": "{}",
            "static/a.js": "a",
            "static/__MACOSX/sub/y": "x",
        ])
        #expect(CashTreesPWASameVersionRule.treeDigest(at: dir) == "4719b314e0063234ce5458f1be863c70956592c53e4a2a8c4eb07e25996aa129")
    }

    @Test func sameVersionNoRecordDifferentTreeReinstalls() throws {
        let action = CashTreesPWASameVersionRule.decideSameVersion(
            activeRecord: nil, embeddedTreeDigest: "embedded", embeddedZipSha256: "zip",
            activeTreeDigest: { "legacy" }
        )
        #expect(action == .reinstall(reason: "no record, tree digest differs from embedded build (same version)"))
    }

    @Test func sameVersionNoRecordSameTreeRecordsAndKeeps() throws {
        let action = CashTreesPWASameVersionRule.decideSameVersion(
            activeRecord: nil, embeddedTreeDigest: "same", embeddedZipSha256: "zip",
            activeTreeDigest: { "same" }
        )
        #expect(action == .recordLegacy(treeDigest: "same", reason: "no record, tree digest matches embedded build"))
    }

    @Test func noEmbeddedManifestKeepsWithoutDigesting() throws {
        var computed = false
        let action = CashTreesPWASameVersionRule.decideSameVersion(
            activeRecord: nil, embeddedTreeDigest: nil, embeddedZipSha256: nil,
            activeTreeDigest: { computed = true; return "x" }
        )
        #expect(action == .keep(reason: "no record and no embedded tree digest: keep, log only"))
        #expect(computed == false)
    }

    @Test func otaRecordIsNeverOverwrittenBySameVersion() throws {
        let record = CashTreesPWASourceRecord(source: .ota, ver: "0.53.42", zipSha256: nil, treeDigest: nil)
        let action = CashTreesPWASameVersionRule.decideSameVersion(
            activeRecord: record, embeddedTreeDigest: "embedded", embeddedZipSha256: "zip",
            activeTreeDigest: { Issue.record("digest must not be computed for an OTA record"); return nil }
        )
        #expect(action == .keep(reason: "active from OTA: never overwritten by the same version"))
    }

    @Test func bundledRecordWithDifferentZipReinstallsAndMatchingKeeps() throws {
        let differs = CashTreesPWASourceRecord(source: .bundled, ver: "0.53.42", zipSha256: "old", treeDigest: nil)
        #expect(CashTreesPWASameVersionRule.decideSameVersion(
            activeRecord: differs, embeddedTreeDigest: nil, embeddedZipSha256: "new",
            activeTreeDigest: { nil }
        ) == .reinstall(reason: "bundled record differs from embedded ZIP (same version)"))
        let same = CashTreesPWASourceRecord(source: .bundled, ver: "0.53.42", zipSha256: "new", treeDigest: nil)
        #expect(CashTreesPWASameVersionRule.decideSameVersion(
            activeRecord: same, embeddedTreeDigest: nil, embeddedZipSha256: "new",
            activeTreeDigest: { nil }
        ) == .keep(reason: "bundled record matches embedded ZIP"))
    }

    @Test func legacyRecordIsKeptAndNotRecomputed() throws {
        let legacy = CashTreesPWASourceRecord(source: .legacyVerified, ver: "0.53.42", zipSha256: nil, treeDigest: "t")
        let action = CashTreesPWASameVersionRule.decideSameVersion(
            activeRecord: legacy, embeddedTreeDigest: "embedded", embeddedZipSha256: "zip",
            activeTreeDigest: { Issue.record("legacy record must not trigger a recompute"); return nil }
        )
        #expect(action == .keep(reason: "legacy record: tree already verified against the embedded build"))
    }

    @Test func recordRoundTripsThroughJSON() throws {
        let record = CashTreesPWASourceRecord(source: .legacyVerified, ver: "0.53.42", zipSha256: nil, treeDigest: "abc")
        let data = try JSONEncoder().encode(record)
        #expect(try JSONDecoder().decode(CashTreesPWASourceRecord.self, from: data) == record)
    }

    @Test func treeDigestTimingIsRecorded() throws {
        // About 18 MB in 104 files, the size measured for the walk-device active directory.
        let blob = String(repeating: "a", count: 180_000)
        var files: [String: String] = ["index.html": "<html>"]
        for i in 0..<100 { files["static/js/chunk\(i).js"] = blob }
        let root = try makeTree(files)
        let start = Date()
        let digest = CashTreesPWASameVersionRule.treeDigest(at: root)
        let elapsed = Date().timeIntervalSince(start)
        print("[PWA-TIMING] treeDigest 18MB/101 files: \(String(format: "%.3f", elapsed)) s")
        #expect(digest != nil)
    }
}
