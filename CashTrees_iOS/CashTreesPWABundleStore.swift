//
//  CashTreesPWABundleStore.swift
//  CashTrees_iOS
//

import Foundation
import ZIPFoundation

extension Notification.Name {
    static let cashTreesEmbeddedPwaUpdateAvailable = Notification.Name("cashTreesEmbeddedPwaUpdateAvailable")
}

/// Documents-backed PWA bundle: `active/` (live), `staging/` (downloaded), `backup/` (rollback).
///
/// Wallet / IndexedDB live in WKWebsiteDataStore under `Library/WebKit` (origin
/// `cashtrees-local://localhost`), **not** under `silentpass_pwa/`. Replacing
/// `active/` must never clear website data. Device uninstall is what wipes the
/// wallet — prefer install-over only (the device install rule).
final class CashTreesPWABundleStore {
    static let shared = CashTreesPWABundleStore()

    private let fileManager = FileManager.default
    private let lock = NSLock()

    let rootDir: URL
    let activeDir: URL
    let stagingDir: URL
    let backupDir: URL

    private(set) var pendingVersion: String?
    /// Active-tree digests computed by this store instance (observed by tests; no behavioral effect).
    private(set) var activeTreeDigestComputations = 0
    /// The last same-version decision of this store instance (observed by tests; no behavioral effect).
    private(set) var lastSameVersionDecision = ""

    private init() {
        guard let documents = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            fatalError("Documents directory unavailable")
        }
        rootDir = documents.appendingPathComponent("silentpass_pwa", isDirectory: true)
        activeDir = rootDir.appendingPathComponent("active", isDirectory: true)
        stagingDir = rootDir.appendingPathComponent("staging", isDirectory: true)
        backupDir = rootDir.appendingPathComponent("backup", isDirectory: true)
        pendingVersion = Self.readPendingVersion(from: stagingDir)
    }

    /// Test seam: the same layout under an explicit root (the app uses `shared`).
    init(testRootDir: URL) {
        rootDir = testRootDir
        activeDir = rootDir.appendingPathComponent("active", isDirectory: true)
        stagingDir = rootDir.appendingPathComponent("staging", isDirectory: true)
        backupDir = rootDir.appendingPathComponent("backup", isDirectory: true)
        pendingVersion = Self.readPendingVersion(from: stagingDir)
    }

    func bootstrapIfNeeded() throws {
        let zip = Bundle.main.url(forResource: "SilentPassUI", withExtension: "zip")
        let facts = Self.embeddedBuildFacts()
        try bootstrap(
            bundledZip: zip,
            embeddedTreeDigest: facts?.treeDigest,
            embeddedZipSha256: facts?.zipSha256
        )
    }

    /// Build-time identity of the embedded ZIP (BeamioPWABuild.json, written by scripts/pwa-embed-digest.sh).
    /// nil when the build did not record it: the same-version rule then keeps the active directory.
    static func embeddedBuildFacts(bundle: Bundle = .main) -> (ver: String, zipSha256: String, treeDigest: String)? {
        guard let url = bundle.url(forResource: "BeamioPWABuild", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ver = obj["ver"] as? String, !ver.isEmpty,
              let zip = obj["zipSha256"] as? String, !zip.isEmpty,
              let tree = obj["treeDigest"] as? String, !tree.isEmpty
        else { return nil }
        return (ver, zip, tree)
    }

    /// Core bootstrap with injected embedded-build facts (tests pass fixtures; the app passes Bundle values).
    func bootstrap(bundledZip zipOptional: URL?, embeddedTreeDigest: String?, embeddedZipSha256: String?) throws {
        lock.lock()
        defer { lock.unlock() }
        try fileManager.createDirectory(at: rootDir, withIntermediateDirectories: true)
        recoverInterruptedSwap()
        guard let zipPath = zipOptional else {
            if hasValidBundle(at: activeDir) { return }
            throw NSError(
                domain: "CashTreesPWABundleStore",
                code: 404,
                userInfo: [NSLocalizedDescriptionKey: "SilentPassUI.zip missing from app bundle"]
            )
        }
        let bundledDir = rootDir.appendingPathComponent("bundled", isDirectory: true)
        if fileManager.fileExists(atPath: bundledDir.path) {
            try? fileManager.removeItem(at: bundledDir)
        }
        try fileManager.createDirectory(at: bundledDir, withIntermediateDirectories: true)
        try fileManager.unzipItem(at: zipPath, to: bundledDir)
        removeMacOsMetadata(from: bundledDir)
        guard hasValidBundle(at: bundledDir) else {
            try? fileManager.removeItem(at: bundledDir)
            throw NSError(
                domain: "CashTreesPWABundleStore",
                code: 500,
                userInfo: [NSLocalizedDescriptionKey: "Bundled SilentPassUI.zip did not contain index.html"]
            )
        }
        let activeIsValid = hasValidBundle(at: activeDir)
        let activeUsesEmbeddedPaths = activeIsValid && usesEmbeddedAssetPaths(at: activeDir)
        // Force-quit CallKit wake needs HTTP /api/registerPushDevice so ios_voip
        // reaches the API when mailbox SI has no push_device_register. A newer
        // Documents active (e.g. 0.52.852 OTA without HTTP) must not stick over
        // a bundled build that includes the HTTP fallback.
        let activeHasPushHttp = activeIsValid && bundleHasRegisterPushDeviceHttp(at: activeDir)
        let bundledHasPushHttp = bundleHasRegisterPushDeviceHttp(at: bundledDir)
        let activeVersion = activeIsValid ? readUpdateInfo(from: activeDir)?.ver : nil
        let bundledVersion = readUpdateInfo(from: bundledDir)?.ver
        var shouldInstallBundled =
            !activeIsValid
            || !activeUsesEmbeddedPaths
            || (bundledHasPushHttp && !activeHasPushHttp)
            || (
                activeVersion != nil
                    && bundledVersion != nil
                    && Self.isSemverNewer(oldVer: activeVersion!, newVer: bundledVersion!)
            )
        // Same version, different bytes (same-version repair design): decide by provenance, never by version alone.
        if !shouldInstallBundled, activeIsValid, let av = activeVersion, let bv = bundledVersion, av == bv {
            let action = CashTreesPWASameVersionRule.decideSameVersion(
                activeRecord: readSourceRecord(at: activeDir),
                embeddedTreeDigest: embeddedTreeDigest,
                embeddedZipSha256: embeddedZipSha256,
                activeTreeDigest: {
                    self.activeTreeDigestComputations += 1
                    return CashTreesPWASameVersionRule.treeDigest(at: self.activeDir, fileManager: self.fileManager)
                }
            )
            switch action {
            case .keep(let reason):
                lastSameVersionDecision = "keep: \(reason)"
                print("[PWA] same-version keep ver=\(av): \(reason)")
            case .recordLegacy(let tree, let reason):
                lastSameVersionDecision = "recordLegacy: \(reason)"
                print("[PWA] same-version record legacy ver=\(av): \(reason)")
                writeSourceRecord(
                    CashTreesPWASourceRecord(source: .legacyVerified, ver: av, zipSha256: nil, treeDigest: tree),
                    at: activeDir
                )
            case .reinstall(let reason):
                lastSameVersionDecision = "reinstall: \(reason)"
                print("[PWA] same-version reinstall ver=\(av): \(reason)")
                shouldInstallBundled = true
            }
        }
        if !shouldInstallBundled {
            try? fileManager.removeItem(at: bundledDir)
            return
        }
        // Documents-only swap with a recoverable step order: active -> active.prev, bundled -> active, record, drop prev.
        // Do not touch WKWebsiteDataStore / Library/WebKit.
        let previous = rootDir.appendingPathComponent(CashTreesPWASameVersionRule.previousActiveName, isDirectory: true)
        if fileManager.fileExists(atPath: previous.path) {
            try? fileManager.removeItem(at: previous)
        }
        let hadActive = fileManager.fileExists(atPath: activeDir.path)
        if hadActive {
            try fileManager.moveItem(at: activeDir, to: previous)
        }
        do {
            try fileManager.moveItem(at: bundledDir, to: activeDir)
        } catch {
            if hadActive { try? fileManager.moveItem(at: previous, to: activeDir) }
            throw error
        }
        writeSourceRecord(
            CashTreesPWASourceRecord(
                source: .bundled,
                ver: bundledVersion ?? "",
                zipSha256: embeddedZipSha256,
                treeDigest: nil
            ),
            at: activeDir
        )
        try? fileManager.removeItem(at: previous)
    }

    /// Restores an interrupted swap (design r3 §4): if `active` is missing and `active.prev` exists, move it back;
    /// if both exist, the swap completed before the prev was dropped, so keep `active` and drop the stale prev.
    func recoverInterruptedSwap() {
        // A record temp file is never written inside the tree (it lives beside the tree), so a stray one here is a
        // leftover of an interrupted write. Clear it before any gate check reads the active tree.
        try? fileManager.removeItem(at: recordTempURL(for: activeDir))
        try? fileManager.removeItem(at: activeDir.appendingPathComponent(CashTreesPWASameVersionRule.sourceTmpFileName))
        let previous = rootDir.appendingPathComponent(CashTreesPWASameVersionRule.previousActiveName, isDirectory: true)
        guard fileManager.fileExists(atPath: previous.path) else { return }
        if fileManager.fileExists(atPath: activeDir.path) {
            try? fileManager.removeItem(at: previous)
        } else {
            try? fileManager.moveItem(at: previous, to: activeDir)
        }
    }

    /// The record temp file for a tree: beside the tree (`<root>/.<name>.source.json.tmp`, e.g. `.active.source.json.tmp`), never inside it.
    private func recordTempURL(for dir: URL) -> URL {
        dir.deletingLastPathComponent().appendingPathComponent(".\(dir.lastPathComponent)\(CashTreesPWASameVersionRule.sourceTmpFileName)")
    }

    private func readSourceRecord(at dir: URL) -> CashTreesPWASourceRecord? {
        let url = dir.appendingPathComponent(CashTreesPWASameVersionRule.sourceFileName)
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(CashTreesPWASourceRecord.self, from: data)
    }

    /// Atomic: write a temporary file, then rename over the record (design r3 §2).
    private func writeSourceRecord(_ record: CashTreesPWASourceRecord, at dir: URL) {
        guard let data = try? JSONEncoder().encode(record) else { return }
        let tmp = recordTempURL(for: dir)
        let final = dir.appendingPathComponent(CashTreesPWASameVersionRule.sourceFileName)
        do {
            try data.write(to: tmp, options: .atomic)
            if fileManager.fileExists(atPath: final.path) {
                try fileManager.removeItem(at: final)
            }
            try fileManager.moveItem(at: tmp, to: final)
        } catch {
            print("[PWA] source record write failed in \(dir.lastPathComponent): \(error.localizedDescription)")
            try? fileManager.removeItem(at: tmp)
        }
    }

    func activeRootDirectory() -> URL {
        lock.lock()
        defer { lock.unlock() }
        return activeDir
    }

    func activeVersion() -> String {
        readUpdateInfo(from: activeDir)?.ver ?? "0.0.0"
    }

    /// Checks the active content under the same lock used by bootstrap and OTA promotion.
    /// Native bridge trust must fail closed if the extracted page differs from the reviewed ZIP.
    func activeBundleMatches(expectedVersion: String, expectedTreeSHA256: String, digest: (URL) -> String?) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard hasValidBundle(at: activeDir), readUpdateInfo(from: activeDir)?.ver == expectedVersion,
              let actual = digest(activeDir)
        else { return false }
        return actual == expectedTreeSHA256
    }

    func activeTreeSHA256(digest: (URL) -> String?) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard hasValidBundle(at: activeDir) else { return nil }
        return digest(activeDir)
    }

    func resolveFileURL(for requestPath: String) -> URL? {
        let root = activeRootDirectory()
        return Self.resolveContainedFile(root: root, requestPath: requestPath, fileManager: fileManager)
    }

    static func resolveContainedFile(root: URL, requestPath: String, fileManager: FileManager = .default) -> URL? {
        // `requestPath` is URLComponents.percentEncodedPath. Decode exactly once, then
        // reject traversal before touching the filesystem. Encoded slashes are decoded
        // before checking components; residual percent escapes are rejected so a second
        // decoder cannot turn `%252e%252e` into a traversal segment later.
        guard let decoded = requestPath.removingPercentEncoding,
              !decoded.contains("%"),
              !decoded.contains("\\"), !decoded.unicodeScalars.contains(where: { $0.value == 0 })
        else { return nil }
        let trimmed = decoded.hasPrefix("/") ? String(decoded.dropFirst()) : decoded
        let components = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        guard !components.contains(where: { $0 == "." || $0 == ".." }) else { return nil }

        let relative = trimmed.isEmpty ? "index.html" : trimmed
        guard let rootPath = canonicalPath(root, fileManager: fileManager) else { return nil }
        let candidate = root.appendingPathComponent(relative).standardizedFileURL
        if let canonical = canonicalPath(candidate, fileManager: fileManager),
           isContained(canonical, by: rootPath), fileManager.fileExists(atPath: canonical.path) {
            return canonical
        }
        // Client-side routes without an extension use index.html. Never use this
        // fallback for a path containing traversal or for a path that escaped root.
        if !relative.contains("."),
           let index = canonicalPath(root.appendingPathComponent("index.html"), fileManager: fileManager),
           isContained(index, by: rootPath), fileManager.fileExists(atPath: index.path) {
            return index
        }
        return nil
    }

    private static func canonicalPath(_ url: URL, fileManager: FileManager) -> URL? {
        let resolved = url.resolvingSymlinksInPath().standardizedFileURL
        guard fileManager.fileExists(atPath: resolved.path) else { return nil }
        return resolved
    }

    private static func isContained(_ candidate: URL, by root: URL) -> Bool {
        let rootPath = root.path.hasSuffix("/") ? root.path : root.path + "/"
        return candidate.path == root.path || candidate.path.hasPrefix(rootPath)
    }

    func installDownloadToStaging(from zipFile: URL, expectedVersion: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if fileManager.fileExists(atPath: stagingDir.path) {
            try fileManager.removeItem(at: stagingDir)
        }
        try fileManager.createDirectory(at: stagingDir, withIntermediateDirectories: true)
        try fileManager.unzipItem(at: zipFile, to: stagingDir)
        removeMacOsMetadata(from: stagingDir)
        guard hasValidBundle(at: stagingDir) else {
            try? fileManager.removeItem(at: stagingDir)
            pendingVersion = nil
            throw NSError(
                domain: "CashTreesPWABundleStore",
                code: 500,
                userInfo: [NSLocalizedDescriptionKey: "Downloaded bundle missing index.html"]
            )
        }
        // Persist version for cold-start pending restore (zip usually includes update.json).
        let info = CashTreesPWAUpdateInfo(ver: expectedVersion, filename: "SilentPassUI-\(expectedVersion).zip")
        if let data = try? JSONEncoder().encode(info) {
            try? data.write(to: stagingDir.appendingPathComponent("update.json"), options: .atomic)
        }
        pendingVersion = expectedVersion
    }

    func promoteStagingToActive() throws {
        lock.lock()
        defer { lock.unlock() }
        // `pendingVersion` is an in-memory hint and can be lost when the
        // WebView/app lifecycle recreates the store. The staging directory is
        // the durable source of truth for an OTA update.
        pendingVersion = Self.readPendingVersion(from: stagingDir)
        guard hasValidBundle(at: stagingDir) else {
            pendingVersion = nil
            throw NSError(
                domain: "CashTreesPWABundleStore",
                code: 404,
                userInfo: [NSLocalizedDescriptionKey: "No staged PWA update"]
            )
        }
        if fileManager.fileExists(atPath: backupDir.path) {
            try? fileManager.removeItem(at: backupDir)
        }
        if fileManager.fileExists(atPath: activeDir.path) {
            try fileManager.moveItem(at: activeDir, to: backupDir)
        }
        try fileManager.moveItem(at: stagingDir, to: activeDir)
        // Provenance: an OTA-promoted active is never overwritten by the same version (design r3 §3).
        if let ota = readUpdateInfo(from: activeDir)?.ver {
            writeSourceRecord(
                CashTreesPWASourceRecord(source: .ota, ver: ota, zipSha256: nil, treeDigest: nil),
                at: activeDir
            )
        }
        pendingVersion = nil
    }

    func clearStaging() {
        lock.lock()
        defer { lock.unlock() }
        try? fileManager.removeItem(at: stagingDir)
        pendingVersion = nil
    }

    func hasPendingUpdate() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if let diskVersion = Self.readPendingVersion(from: stagingDir) {
            pendingVersion = diskVersion
        } else {
            pendingVersion = nil
        }
        return pendingVersion != nil && hasValidBundle(at: stagingDir)
    }

    func pendingUpdateVersion() -> String? {
        lock.lock()
        defer { lock.unlock() }
        pendingVersion = Self.readPendingVersion(from: stagingDir)
        guard pendingVersion != nil, hasValidBundle(at: stagingDir) else { return nil }
        return pendingVersion
    }

    // MARK: - Helpers

    private func hasValidBundle(at dir: URL) -> Bool {
        fileManager.fileExists(atPath: dir.appendingPathComponent("index.html").path)
    }

    /// The app shell serves the PWA at the root of `cashtrees-local://`.
    /// Older consumer bundles were built for `/app/`, so their JS/CSS requests
    /// pointed at a non-existent local `/app` directory and left only the splash
    /// logo visible. Treat those bundles as incompatible even when their
    /// semver is unchanged, so an app update repairs existing installations.
    private func usesEmbeddedAssetPaths(at dir: URL) -> Bool {
        let indexURL = dir.appendingPathComponent("index.html")
        guard let html = try? String(contentsOf: indexURL, encoding: .utf8) else {
            return false
        }
        return !html.contains("src=\"/app/")
            && !html.contains("href=\"/app/")
    }

    /// True when any JS chunk posts to `/api/registerPushDevice` (HTTP fallback
    /// for PushKit `ios_voip` when CoNET-SI lacks `push_device_register`).
    private func bundleHasRegisterPushDeviceHttp(at dir: URL) -> Bool {
        let staticDir = dir.appendingPathComponent("static/js", isDirectory: true)
        let fm = fileManager
        guard let enumerator = fm.enumerator(
            at: staticDir,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return false
        }
        let needle = "/api/registerPushDevice"
        while let item = enumerator.nextObject() as? URL {
            guard item.pathExtension == "js",
                  let data = try? Data(contentsOf: item, options: [.mappedIfSafe]),
                  let text = String(data: data, encoding: .utf8)
            else { continue }
            if text.contains(needle) { return true }
        }
        return false
    }

    private func readUpdateInfo(from dir: URL) -> CashTreesPWAUpdateInfo? {
        let url = dir.appendingPathComponent("update.json")
        guard fileManager.fileExists(atPath: url.path),
              let data = try? Data(contentsOf: url),
              let info = try? JSONDecoder().decode(CashTreesPWAUpdateInfo.self, from: data)
        else { return nil }
        return info
    }

    private static func readPendingVersion(from staging: URL) -> String? {
        let fm = FileManager.default
        let index = staging.appendingPathComponent("index.html")
        guard fm.fileExists(atPath: index.path) else { return nil }
        let url = staging.appendingPathComponent("update.json")
        guard fm.fileExists(atPath: url.path),
              let data = try? Data(contentsOf: url),
              let info = try? JSONDecoder().decode(CashTreesPWAUpdateInfo.self, from: data)
        else { return nil }
        return info.ver
    }

    private func removeMacOsMetadata(from directory: URL) {
        let macosx = directory.appendingPathComponent("__MACOSX", isDirectory: true)
        if fileManager.fileExists(atPath: macosx.path) {
            try? fileManager.removeItem(at: macosx)
        }
    }

    static func isSemverNewer(oldVer: String, newVer: String) -> Bool {
        let oldParts = oldVer.split(separator: ".").map { Int($0) ?? 0 }
        let newParts = newVer.split(separator: ".").map { Int($0) ?? 0 }
        let count = max(oldParts.count, newParts.count)
        for i in 0..<count {
            let o = i < oldParts.count ? oldParts[i] : 0
            let n = i < newParts.count ? newParts[i] : 0
            if n > o { return true }
            if n < o { return false }
        }
        return false
    }
}
