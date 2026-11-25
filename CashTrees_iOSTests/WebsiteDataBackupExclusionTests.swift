import Foundation
import Testing
@testable import CashTrees_iOS

// The shell's backup guard for the page's website data: only Library/WebKit/<bundle id>/WebsiteData is flagged; a missing
// directory is not an error and creates nothing; a rebuilt directory is flagged again on the next run.
struct WebsiteDataBackupExclusionTests {
    private func excluded(_ url: URL) -> Bool {
        // a fresh URL: a URL instance caches its resource values
        (try? URL(fileURLWithPath: url.path).resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup == true
    }

    private func makeLibrary() throws -> URL {
        let lib = FileManager.default.temporaryDirectory.appendingPathComponent("websitedata-backup-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: lib, withIntermediateDirectories: true)
        return lib
    }

    @Test func onlyTheWebsiteDataDirectoryIsFlagged() throws {
        let lib = try makeLibrary()
        defer { try? FileManager.default.removeItem(at: lib) }
        let fm = FileManager.default
        let target = CashTreesWebsiteDataBackupExclusion.directory(library: lib, bundleId: "com.example.app")
        let origin = target.appendingPathComponent("Default/o/o/IndexedDB", isDirectory: true)
        let siblings = [
            lib.appendingPathComponent("WebKit/com.example.app/Other", isDirectory: true),
            lib.appendingPathComponent("WebKit/other.bundle/WebsiteData", isDirectory: true),
            lib.appendingPathComponent("Preferences", isDirectory: true),
            lib.appendingPathComponent("Application Support", isDirectory: true),
        ]
        for d in [origin] + siblings { try fm.createDirectory(at: d, withIntermediateDirectories: true) }
        let file = origin.appendingPathComponent("IndexedDB.sqlite3")
        try Data("x".utf8).write(to: file)

        #expect(CashTreesWebsiteDataBackupExclusion.apply(library: lib, bundleId: "com.example.app"))
        #expect(excluded(target), "WebsiteData is flagged")
        #expect(try Data(contentsOf: file) == Data("x".utf8), "no website data is changed")
        for d in siblings { #expect(!excluded(d), "\(d.lastPathComponent) is not flagged") }
        #expect(!excluded(lib.appendingPathComponent("WebKit")), "the WebKit parent is not flagged")
        #expect(!excluded(lib), "Library is not flagged")
    }

    @Test func aMissingDirectoryIsNotAnErrorAndARebuiltOneIsFlaggedAgain() throws {
        let lib = try makeLibrary()
        defer { try? FileManager.default.removeItem(at: lib) }
        let target = CashTreesWebsiteDataBackupExclusion.directory(library: lib, bundleId: "com.example.app")
        #expect(!CashTreesWebsiteDataBackupExclusion.apply(library: lib, bundleId: "com.example.app"), "missing: nothing to flag")
        #expect(!FileManager.default.fileExists(atPath: target.path), "nothing is created")
        #expect(!CashTreesWebsiteDataBackupExclusion.apply(library: nil, bundleId: "com.example.app"))
        #expect(!CashTreesWebsiteDataBackupExclusion.apply(library: lib, bundleId: ""))

        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        #expect(CashTreesWebsiteDataBackupExclusion.apply(library: lib, bundleId: "com.example.app"))
        // WebKit rebuilds the directory: the new one has no flag until the next cold start
        try FileManager.default.removeItem(at: target)
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        #expect(!excluded(target))
        #expect(CashTreesWebsiteDataBackupExclusion.apply(library: lib, bundleId: "com.example.app"), "flagged again on the next run")
        #expect(excluded(target))
    }
}
