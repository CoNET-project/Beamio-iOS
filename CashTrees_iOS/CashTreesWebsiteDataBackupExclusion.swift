import Foundation

/// Keeps the page's website data (`Library/WebKit/<bundle id>/WebsiteData`: the IndexedDB and LocalStorage of
/// cashtrees-local://localhost) out of iCloud and computer backups.
///
/// WebKit already marks its per-origin directory as excluded; this is the shell's own guard, the same on every iOS version.
/// It runs on every cold start, before the WebView is created: when WebKit rebuilds the directory, the flag comes back on
/// the next cold start. A missing directory (a first launch) is not an error and nothing is created. Only the flag is
/// set: no website data is read, moved or changed.
///
/// Cost: page preferences (for example the language) do not move to a new device through a backup. The wallet is
/// restored on a new device anyway (its keychain items are this-device-only).
enum CashTreesWebsiteDataBackupExclusion {
    /// `Library/WebKit/<bundle id>/WebsiteData` under `library`.
    static func directory(library: URL, bundleId: String) -> URL {
        library.appendingPathComponent("WebKit", isDirectory: true)
            .appendingPathComponent(bundleId, isDirectory: true)
            .appendingPathComponent("WebsiteData", isDirectory: true)
    }

    /// Sets the flag when the directory exists. Returns true when the directory is excluded afterwards.
    @discardableResult
    static func apply(
        library: URL? = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first,
        bundleId: String? = Bundle.main.bundleIdentifier
    ) -> Bool {
        guard let library, let bundleId, !bundleId.isEmpty else { return false }
        let dir = directory(library: library, bundleId: bundleId)
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else { return false }
        CashTreesPWABundleStore.excludeFromBackup(dir)
        return (try? dir.resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup == true
    }
}
