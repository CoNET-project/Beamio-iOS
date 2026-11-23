//
//  CashTreesPWASameVersionRule.swift
//  CashTrees_iOS
//
//  Same-version repair rule for the Documents-backed PWA (same-version repair design).
//  Pure functions only: the store decides when to touch the disk; these decide what to do.
//

import CryptoKit
import Foundation

/// Provenance of the active PWA directory, written as `active/.source.json` (atomic tmp + rename).
struct CashTreesPWASourceRecord: Codable, Equatable {
    enum Source: String, Codable {
        case bundled
        case ota
        /// Same version, no record before: the tree digest matched the embedded build, so the record was written once.
        case legacyVerified
    }

    let source: Source
    let ver: String
    let zipSha256: String?
    let treeDigest: String?
}

enum CashTreesPWAReunpackAction: Equatable {
    /// Keep the active directory unchanged.
    case keep(reason: String)
    /// Keep the active directory and write a `legacy-verified` record with this tree digest (no later recompute).
    case recordLegacy(treeDigest: String, reason: String)
    /// Replace the active directory with the embedded build.
    case reinstall(reason: String)
}

enum CashTreesPWASameVersionRule {
    static let sourceFileName = ".source.json"
    static let sourceTmpFileName = ".source.json.tmp"
    static let previousActiveName = "active.prev"

    /// Names excluded from the tree digest (only these three classes; never widen).
    /// `.source.json` (the provenance record), any-level `__MACOSX`, and `._*` AppleDouble files.
    static func isExcludedFromDigest(relativePath: String) -> Bool {
        let parts = relativePath.split(separator: "/").map(String.init)
        if parts.contains("__MACOSX") { return true }
        guard let name = parts.last else { return true }
        if name == sourceFileName { return true }
        if name.hasPrefix("._") { return true }
        return false
    }

    /// Number of tree digests computed in this process (observed by tests; no behavioral effect).
    private(set) static var treeDigestComputeCount = 0
    private static let countLock = NSLock()

    /// Tree digest: every regular file (filtered as above), sorted by UTF-8 relative path,
    /// each contributing `path NUL sha256(content) LF`; the result is the SHA-256 of that text, lower-case hex.
    /// Fails closed (nil) on a symbolic link, an unreadable entry, or a read failure.
    static func treeDigest(at dir: URL, fileManager: FileManager = .default) -> String? {
        countLock.lock()
        treeDigestComputeCount += 1
        countLock.unlock()
        guard let enumerator = fileManager.enumerator(
            at: dir, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey]
        ) else { return nil }
        var entries: [(path: String, url: URL)] = []
        let rootPath = dir.standardizedFileURL.path
        for case let url as URL in enumerator {
            guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else { return nil }
            if values.isSymbolicLink == true { return nil }
            guard values.isRegularFile == true else { continue }
            let full = url.standardizedFileURL.path
            guard full.hasPrefix(rootPath + "/") else { return nil }
            let rel = String(full.dropFirst(rootPath.count + 1))
            if isExcludedFromDigest(relativePath: rel) { continue }
            entries.append((rel, url))
        }
        entries.sort { Array($0.path.utf8).lexicographicallyPrecedes(Array($1.path.utf8)) }
        var manifest = ""
        for entry in entries {
            guard let digest = fileSHA256(at: entry.url) else { return nil }
            manifest += entry.path + "\u{0}" + digest + "\n"
        }
        return sha256Hex(Data(manifest.utf8))
    }

    static func fileSHA256(at url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = handle.readData(ofLength: 1 << 20)
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Decision for the case where the active and embedded versions are equal and the active directory is valid.
    /// - Parameters:
    ///   - activeRecord: `.source.json` of the active directory, nil when absent or unreadable.
    ///   - embeddedTreeDigest: build-time tree digest of the embedded build (nil when the build did not record it).
    ///   - embeddedZipSha256: build-time SHA-256 of the embedded ZIP (nil when not recorded).
    ///   - activeTreeDigest: computed lazily, only on the one branch that needs it.
    static func decideSameVersion(
        activeRecord: CashTreesPWASourceRecord?,
        embeddedTreeDigest: String?,
        embeddedZipSha256: String?,
        activeTreeDigest: () -> String?
    ) -> CashTreesPWAReunpackAction {
        if let record = activeRecord {
            switch record.source {
            case .ota:
                return .keep(reason: "active from OTA: never overwritten by the same version")
            case .legacyVerified:
                return .keep(reason: "legacy record: tree already verified against the embedded build")
            case .bundled:
                guard let embeddedZip = embeddedZipSha256 else {
                    return .keep(reason: "embedded ZIP digest not recorded: keep")
                }
                if let recorded = record.zipSha256, recorded == embeddedZip {
                    return .keep(reason: "bundled record matches embedded ZIP")
                }
                return .reinstall(reason: "bundled record differs from embedded ZIP (same version)")
            }
        }
        // No record: only a provable match with the embedded build's tree may be repaired or recorded.
        guard let manifest = embeddedTreeDigest else {
            return .keep(reason: "no record and no embedded tree digest: keep, log only")
        }
        guard let active = activeTreeDigest() else {
            return .keep(reason: "active tree digest unavailable: keep")
        }
        if active == manifest {
            return .recordLegacy(treeDigest: active, reason: "no record, tree digest matches embedded build")
        }
        return .reinstall(reason: "no record, tree digest differs from embedded build (same version)")
    }
}
