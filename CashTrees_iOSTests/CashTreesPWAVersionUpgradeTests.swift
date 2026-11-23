import Foundation
import Testing
@testable import CashTrees_iOS

/// Standard OTA version rules for the 105 build. Per the project decision, the hotfix is 0.52.933 and goes through the
/// normal strict comparison (no same-version replacement). Nothing is lowered; a failed install keeps the old package.
struct CashTreesPWAVersionUpgradeTests {
    static let hotfix = "0.52.933"

    @Test func embedded0_52_931UpgradesTo0_52_933() {
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.931", newVer: Self.hotfix))
    }

    @Test func active0_52_932UpgradesTo0_52_933() {
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.932", newVer: Self.hotfix))
    }

    @Test func remoteLowerThanActiveIsNeverApplied() {
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.933", newVer: "0.52.931") == false)
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.933", newVer: "0.52.932") == false)
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.932", newVer: "0.52.931") == false)
    }

    @Test func sameVersionIsNotReinstalled() {
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: Self.hotfix, newVer: Self.hotfix) == false)
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.931", newVer: "0.52.931") == false)
    }

    @Test func numericComparisonNotLexicographic() {
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.9", newVer: "0.52.10"))
        #expect(CashTreesPWABundleStore.isSemverNewer(oldVer: "0.52.932", newVer: "0.52.933"))
    }

    private func tempRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("pwa-upgrade-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    private func writeBundle(at dir: URL, ver: String) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try "<html></html>".write(to: dir.appendingPathComponent("index.html"), atomically: true, encoding: .utf8)
        try #"{"ver":"\#(ver)","filename":"SilentPassUI-\#(ver).zip"}"#.write(to: dir.appendingPathComponent("update.json"), atomically: true, encoding: .utf8)
    }

    @Test func normalUpgradeReplacesTheActivePackage() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeBundle(at: store.activeDir, ver: "0.52.931")
        try writeBundle(at: store.stagingDir, ver: Self.hotfix)
        try store.promoteStagingToActive()
        #expect(store.activeVersion() == Self.hotfix)
        #expect(!FileManager.default.fileExists(atPath: store.stagingDir.path))
    }

    @Test func failedDownloadKeepsTheOldPackageAndOtherData() throws {
        let root = try tempRoot(); defer { try? FileManager.default.removeItem(at: root) }
        let store = CashTreesPWABundleStore(testRootDir: root)
        try writeBundle(at: store.activeDir, ver: "0.52.932")
        let other = root.appendingPathComponent("other-user-data.txt")
        try "keep".write(to: other, atomically: true, encoding: .utf8)
        // A download that is not a ZIP fails to unzip: nothing is staged, the active package and other data stay.
        let bad = root.appendingPathComponent("bad.zip")
        try "not a zip".write(to: bad, atomically: true, encoding: .utf8)
        #expect(throws: (any Error).self) {
            try store.installDownloadToStaging(from: bad, expectedVersion: Self.hotfix)
        }
        #expect(store.activeVersion() == "0.52.932")
        #expect(store.pendingVersion == nil)
        #expect((try? String(contentsOf: other, encoding: .utf8)) == "keep")
    }
}
