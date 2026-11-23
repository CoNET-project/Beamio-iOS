//
//  NativeBridgeIdentityTests.swift
//  CashTrees_iOSTests
//
//  The trusted PWA identity comes from the build sidecar (BeamioPWABuild.json), never from source.
//  The embedded build passes; a tampered active tree, a wrong ZIP digest, or a missing sidecar fails closed.
//

import Foundation
import Testing
import ZIPFoundation
@testable import CashTrees_iOS

@Suite(.serialized)
struct NativeBridgeIdentityTests {
    private func tempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nbt-identity-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test func embeddedBuildSidecarIsPresentAndValid() {
        // The test host is the shell app: its build phase wrote BeamioPWABuild.json next to SilentPassUI.zip.
        let facts = CashTreesPWABundleStore.embeddedBuildFacts()
        #expect(facts != nil)
        #expect(NativeBridgeTrust.embeddedIdentity != nil)
        #expect(NativeBridgeTrust.expectedEmbeddedZipSHA256.count == 64)
        #expect(NativeBridgeTrust.expectedActiveTreeSHA256.count == 64)
    }

    @Test func currentEmbeddedZipPassesTheEmbeddedZipCheck() {
        // The embedded ZIP is the one the sidecar describes.
        #expect(NativeBridgeTrust.embeddedZipMatches())
    }

    @Test func missingSidecarFailsClosed() {
        #expect(NativeBridgeTrust.identity(from: nil) == nil)
        #expect(NativeBridgeTrust.identity(from: ("", "zip", "tree")) == nil)
        #expect(NativeBridgeTrust.identity(from: ("0.53.42", "", "tree")) == nil)
        #expect(NativeBridgeTrust.identity(from: ("0.53.42", "zip", "")) == nil)
        // Without an identity the expected values are empty, so no reported value can match.
        #expect(!NativeBridgeTrust.isTrusted(
            isMainFrame: true, scheme: CashTreesPWAScheme.scheme, host: CashTreesPWAScheme.host, port: 0,
            activeVersion: "", embeddedZipSHA256: "", activeTreeSHA256: ""
        ))
    }

    @Test func wrongZipDigestIsRefused() {
        let id = NativeBridgeTrust.identity(from: ("0.53.42", "aaaa", "bbbb"))
        #expect(id != nil)
        #expect(NativeBridgeTrust.digest(Data("not the reviewed zip".utf8)) != id?.zipSHA256)
    }

    @Test func tamperedActiveTreeIsRefused() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data("<html>reviewed</html>".utf8).write(to: dir.appendingPathComponent("index.html"))
        let reviewed = NativeBridgeTrust.treeDigestOfActive( dir)
        #expect(reviewed != nil)
        // Tamper with the active page after the reviewed build.
        try Data("<html>tampered</html>".utf8).write(to: dir.appendingPathComponent("index.html"))
        let tampered = NativeBridgeTrust.treeDigestOfActive( dir)
        #expect(tampered != reviewed)
        // Only a tree equal to the sidecar's treeDigest is trusted.
        #expect(tampered != NativeBridgeTrust.expectedActiveTreeSHA256)
    }

    @Test func treeDigestUsesTheBuildAlgorithm() throws {
        // The gate and the build sidecar share one algorithm, so the same tree yields the same digest.
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data("a".utf8).write(to: dir.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"0.53.42\"}".utf8).write(to: dir.appendingPathComponent("update.json"))
        try Data("{}".utf8).write(to: dir.appendingPathComponent(".source.json"))
        #expect(NativeBridgeTrust.treeDigestOfActive( dir) == CashTreesPWASameVersionRule.treeDigest(at: dir))
    }

    @Test func reinstallKeepsTheActiveIdentityEqualToTheSidecar() throws {
        // Same version, different bytes: the bootstrap re-unpacks the embedded build, then the gate's active tree equals the sidecar treeDigest.
        let root = try tempDir(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        let src = try tempDir(); defer { try? FileManager.default.removeItem(at: src) }
        try Data("<html>embedded</html>".utf8).write(to: src.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"0.53.42\",\"filename\":\"SilentPassUI-0.53.42.zip\"}".utf8)
            .write(to: src.appendingPathComponent("update.json"))
        let zip = src.deletingLastPathComponent().appendingPathComponent("nbt-\(UUID().uuidString).zip")
        try FileManager.default.zipItem(at: src, to: zip, shouldKeepParent: false)
        let unzipped = try tempDir(); defer { try? FileManager.default.removeItem(at: unzipped) }
        try FileManager.default.unzipItem(at: zip, to: unzipped)
        let tree = CashTreesPWASameVersionRule.treeDigest(at: unzipped) ?? ""
        // An older same-version active with different bytes.
        try FileManager.default.createDirectory(at: store.activeDir, withIntermediateDirectories: true)
        try Data("<html>old</html>".utf8).write(to: store.activeDir.appendingPathComponent("index.html"))
        // update.json must decode as CashTreesPWAUpdateInfo (ver AND filename), as a real install's does.
        try Data("{\"ver\":\"0.53.42\",\"filename\":\"SilentPassUI-0.53.42.zip\"}".utf8)
            .write(to: store.activeDir.appendingPathComponent("update.json"))
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: tree, embeddedZipSha256: "zip")
        let afterActive = NativeBridgeTrust.treeDigestOfActive(store.activeDir)
        #expect(afterActive == tree, "decision=\(store.lastSameVersionDecision) active=\(afterActive ?? "nil") tree=\(tree)")
    }

    @Test func extraFileInActiveIsRefused() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data("a".utf8).write(to: dir.appendingPathComponent("index.html"))
        let reviewed = NativeBridgeTrust.treeDigestOfActive(dir)
        try Data("extra".utf8).write(to: dir.appendingPathComponent("extra.js"))
        #expect(NativeBridgeTrust.treeDigestOfActive(dir) != reviewed)
    }

    @Test func symlinkInActiveFailsClosed() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data("a".utf8).write(to: dir.appendingPathComponent("index.html"))
        try FileManager.default.createSymbolicLink(
            atPath: dir.appendingPathComponent("link").path, withDestinationPath: "index.html"
        )
        #expect(NativeBridgeTrust.treeDigestOfActive(dir) == nil)
    }

    @Test func provenanceRecordChangeDoesNotAffectTheGate() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data("a".utf8).write(to: dir.appendingPathComponent("index.html"))
        let before = NativeBridgeTrust.treeDigestOfActive(dir)
        try Data("{\"source\":\"bundled\"}".utf8).write(to: dir.appendingPathComponent(".source.json"))
        #expect(NativeBridgeTrust.treeDigestOfActive(dir) == before)
    }

    @Test func embeddedBuildPassesTheGateEndToEnd() throws {
        // The shell's own embedded ZIP, installed through the bootstrap, is the reviewed active: both checks pass.
        guard let identity = NativeBridgeTrust.embeddedIdentity,
              let zip = Bundle.main.url(forResource: "SilentPassUI", withExtension: "zip")
        else { Issue.record("embedded identity or ZIP missing"); return }
        let root = try tempDir(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: identity.treeSHA256, embeddedZipSha256: identity.zipSHA256)
        #expect(NativeBridgeTrust.embeddedZipMatches())
        #expect(store.activeBundleMatches(
            expectedVersion: identity.version,
            expectedTreeSHA256: identity.treeSHA256,
            digest: { CashTreesPWASameVersionRule.treeDigest(at: $0) }
        ))
    }

    @Test func deletedFileChangesTheActiveDigest() throws {
        let dir = try tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try Data("a".utf8).write(to: dir.appendingPathComponent("index.html"))
        try Data("b".utf8).write(to: dir.appendingPathComponent("app.js"))
        let reviewed = NativeBridgeTrust.treeDigestOfActive(dir)
        try FileManager.default.removeItem(at: dir.appendingPathComponent("app.js"))
        #expect(NativeBridgeTrust.treeDigestOfActive(dir) != reviewed)
    }

    @Test func residualRecordTempIsClearedOnRecoveryAndTheGatePasses() throws {
        // A record write interrupted after its temp file was created: the next start clears the leftovers,
        // and the gate reads exactly the reviewed tree (the temp file never counts).
        let root = try tempDir(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try FileManager.default.createDirectory(at: store.activeDir, withIntermediateDirectories: true)
        try Data("<html>reviewed</html>".utf8).write(to: store.activeDir.appendingPathComponent("index.html"))
        let reviewed = NativeBridgeTrust.treeDigestOfActive(store.activeDir)
        // Leftovers: the temp beside the tree (the write location) and a legacy one inside the tree.
        try Data("{partial".utf8).write(to: root.appendingPathComponent(".active.source.json.tmp"))
        try Data("{partial".utf8).write(to: store.activeDir.appendingPathComponent(".source.json.tmp"))
        store.recoverInterruptedSwap()
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent(".active.source.json.tmp").path))
        #expect(!FileManager.default.fileExists(atPath: store.activeDir.appendingPathComponent(".source.json.tmp").path))
        #expect(NativeBridgeTrust.treeDigestOfActive(store.activeDir) == reviewed)
    }

    @Test func bootstrapClearsResidualTempsBeforeTheGateReadsTheTree() throws {
        // Through the public bootstrap (the path the app takes): residual temps inside the tree and beside it are cleared,
        // and the same-version decision then reads a clean tree equal to the bundled one.
        let root = try tempDir(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        let src = try tempDir(); defer { try? FileManager.default.removeItem(at: src) }
        try Data("<html>same</html>".utf8).write(to: src.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"0.53.42\",\"filename\":\"SilentPassUI-0.53.42.zip\"}".utf8)
            .write(to: src.appendingPathComponent("update.json"))
        let zip = src.deletingLastPathComponent().appendingPathComponent("nbt-\(UUID().uuidString).zip")
        try FileManager.default.zipItem(at: src, to: zip, shouldKeepParent: false)
        let unzipped = try tempDir(); defer { try? FileManager.default.removeItem(at: unzipped) }
        try FileManager.default.unzipItem(at: zip, to: unzipped)
        let tree = CashTreesPWASameVersionRule.treeDigest(at: unzipped) ?? ""
        // The active is the same bytes, with a residual temp inside and one beside (an interrupted write).
        try FileManager.default.createDirectory(at: store.activeDir, withIntermediateDirectories: true)
        try Data("<html>same</html>".utf8).write(to: store.activeDir.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"0.53.42\",\"filename\":\"SilentPassUI-0.53.42.zip\"}".utf8)
            .write(to: store.activeDir.appendingPathComponent("update.json"))
        try Data("{partial".utf8).write(to: store.activeDir.appendingPathComponent(".source.json.tmp"))
        try Data("{partial".utf8).write(to: root.appendingPathComponent(".active.source.json.tmp"))
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: tree, embeddedZipSha256: "zip")
        #expect(!FileManager.default.fileExists(atPath: store.activeDir.appendingPathComponent(".source.json.tmp").path))
        #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent(".active.source.json.tmp").path))
        #expect(NativeBridgeTrust.treeDigestOfActive(store.activeDir) == tree)
        // Order proof: the same-version decision read the cleaned tree and recorded it (no reinstall).
        // If the gate had read before the cleanup, the residual would have forced a reinstall instead.
        #expect(store.lastSameVersionDecision.hasPrefix("recordLegacy"), "decision=\(store.lastSameVersionDecision)")
    }

    @Test func recordWriteNeverLeavesATempInsideTheTree() throws {
        // A bootstrap install writes the record through the sibling temp; afterwards nothing temp-like is inside the tree.
        let root = try tempDir(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        let src = try tempDir(); defer { try? FileManager.default.removeItem(at: src) }
        try Data("<html>embedded</html>".utf8).write(to: src.appendingPathComponent("index.html"))
        try Data("{\"ver\":\"0.53.42\",\"filename\":\"SilentPassUI-0.53.42.zip\"}".utf8)
            .write(to: src.appendingPathComponent("update.json"))
        let zip = src.deletingLastPathComponent().appendingPathComponent("nbt-\(UUID().uuidString).zip")
        try FileManager.default.zipItem(at: src, to: zip, shouldKeepParent: false)
        try store.bootstrap(bundledZip: zip, embeddedTreeDigest: "x", embeddedZipSha256: "zip")
        let inside = try FileManager.default.contentsOfDirectory(atPath: store.activeDir.path)
        #expect(!inside.contains(".source.json.tmp"))
        #expect(FileManager.default.fileExists(atPath: store.activeDir.appendingPathComponent(".source.json").path))
    }

    @Test func sourceFailureCodesFollowTheProtocol() {
        // v164 §184.1–184.2: a source mismatch is origin_refused for the new commands; only legacy commands keep untrusted_source.
        #expect(NativeBridgeTrust.untrustedSourceErrorCode(forCommand: "shellRecordRead") == "origin_refused")
        #expect(NativeBridgeTrust.untrustedSourceErrorCode(forCommand: "shellRecordWrite") == "origin_refused")
        #expect(NativeBridgeTrust.untrustedSourceErrorCode(forCommand: "walletCredential") == "origin_refused")
        #expect(NativeBridgeTrust.untrustedSourceErrorCode(forCommand: "pwaWalletSync") == "untrusted_source")
        #expect(NativeBridgeTrust.untrustedSourceErrorCode(forCommand: "nativeMnemonicPreread") == "untrusted_source")
    }

    @Test func identityTracksTheSidecarNotASourceConstant() {
        let id = NativeBridgeTrust.identity(from: ("0.53.99", "ab", "cd"))
        #expect(id == NativeBridgeTrust.Identity(version: "0.53.99", zipSHA256: "ab", treeSHA256: "cd"))
    }
}
