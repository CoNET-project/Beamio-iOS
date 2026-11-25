//
//  CashTreesPWAColdStart.swift
//  CashTrees_iOS
//
//  Cold-start completion record, light identity (metadata fingerprint), strict version parsing and
//  the policy for an active directory this shell cannot verify.
//
//  The record only decides which bundle a cold start opens and whether the embedded ZIP must be unpacked.
//  It is never a bridge trust input: NativeBridgeTrust takes its expected values from the signed
//  BeamioPWABuild.json and its actual value from a full tree digest of the active directory.
//

import CryptoKit
import Darwin
import Foundation

/// Build-time identity of the embedded ZIP (BeamioPWABuild.json). Any field may be missing in a defective build.
nonisolated struct CashTreesPWAEmbeddedFacts: Equatable {
    let ver: String?
    let zipSha256: String?
    let treeDigest: String?

    /// True when the identity can anchor anything: the ZIP digest and the tree digest are both present.
    var hasIdentity: Bool {
        !(zipSha256 ?? "").isEmpty && !(treeDigest ?? "").isEmpty
    }
}

// MARK: - Strict version parsing

/// Accepts only three numeric segments, each 0 or 1–9 digits without a leading zero. Anything else is an unknown
/// version (nil): never read as 0.
nonisolated enum CashTreesPWAVersion {
    private static let countLock = NSLock()
    /// Number of version order comparisons made in this process (observed by tests and the cold-start log).
    private(set) static var compareCount = 0

    static func parse(_ text: String?) -> [Int]? {
        guard let text, !text.isEmpty else { return nil }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { return nil }
        var out: [Int] = []
        for part in parts {
            guard !part.isEmpty, part.count <= 9, part.allSatisfy({ $0 >= "0" && $0 <= "9" }) else { return nil }
            if part.count > 1 && part.first == "0" { return nil }
            guard let value = Int(part) else { return nil }
            out.append(value)
        }
        return out
    }

    /// One counted comparison: -1 when a < b, 0 when equal, 1 when a > b; nil when either side is unknown (not counted).
    static func order(_ a: String?, _ b: String?) -> Int? {
        guard let x = parse(a), let y = parse(b) else { return nil }
        countLock.lock()
        compareCount += 1
        countLock.unlock()
        for i in 0..<3 where x[i] != y[i] {
            return x[i] < y[i] ? -1 : 1
        }
        return 0
    }

    /// True when `newVer` is strictly newer than `oldVer`; nil when either side is an unknown version (no comparison made).
    static func isStrictlyNewer(old oldVer: String?, new newVer: String?) -> Bool? {
        guard let o = parse(oldVer), let n = parse(newVer) else { return nil }
        countLock.lock()
        compareCount += 1
        countLock.unlock()
        for i in 0..<3 where n[i] != o[i] {
            return n[i] > o[i]
        }
        return false
    }
}

// MARK: - Completion record (v2)

nonisolated struct CashTreesPWAColdStartRecord: Codable, Equatable {
    struct Embedded: Codable, Equatable {
        let zipSha256: String
        let contentDigest: String
        /// Log only: never part of a hit.
        let ver: String?
        /// enabled | identical | older-ignored | same-version-ignored | not-selected | ver-unknown
        let outcome: String
    }

    struct Ota: Codable, Equatable {
        let signedFile: String
        let signedFileSha256: String
        let keyId: String
        let keyTableId: String
        let zipSha256: String
    }

    struct Selected: Codable, Equatable {
        let origin: String
        let contentDigest: String
        /// Log only: never part of a hit.
        let ver: String?
        /// origin=ota only. Used to pick the bundle; never a trust input.
        let ota: Ota?
        let generation: Int
    }

    static let schemaV2 = "beamio.pwa.coldstart.v2"
    /// Selection rule version. Any change to the selection rules must bump it (forces a new decision on every install).
    static let ruleVersion = 2
    static let fileName = "coldstart-record.v2.json"
    static let tmpFileName = ".coldstart-record.v2.json.tmp"
    static let legacyFileNames = ["coldstart-record.v1.json", ".coldstart-record.v1.json.tmp"]

    let schema: String
    let ruleVersion: Int
    let platform: String
    let variant: String
    let installId: String
    /// Log only (not part of a hit since v2).
    let shellBuild: String
    let embedded: Embedded
    let selected: Selected
    let network: String
    let activeFingerprint: String
    let decision: String
    let result: String
    let completedAtUtc: String
}

/// Reads, writes (tmp + fsync + rename + directory fsync) and invalidates the record at the `silentpass_pwa` root.
nonisolated enum CashTreesPWAColdStartRecordIO {
    static func recordURL(root: URL) -> URL { root.appendingPathComponent(CashTreesPWAColdStartRecord.fileName) }
    static func tmpURL(root: URL) -> URL { root.appendingPathComponent(CashTreesPWAColdStartRecord.tmpFileName) }

    /// nil when absent, unreadable or not JSON of this schema.
    static func read(root: URL) -> CashTreesPWAColdStartRecord? {
        guard let data = try? Data(contentsOf: recordURL(root: root)),
              let rec = try? JSONDecoder().decode(CashTreesPWAColdStartRecord.self, from: data),
              rec.schema == CashTreesPWAColdStartRecord.schemaV2
        else { return nil }
        return rec
    }

    /// Deletes the record (and any tmp) and syncs the directory. Called before anything changes the active directory.
    /// Returns false when a record or tmp is still present afterwards: the caller must then not change the active directory.
    @discardableResult
    static func invalidate(root: URL) -> Bool {
        let fm = FileManager.default
        let legacy = CashTreesPWAColdStartRecord.legacyFileNames.map { root.appendingPathComponent($0) }
        for url in [recordURL(root: root), tmpURL(root: root)] + legacy where fm.fileExists(atPath: url.path) {
            do {
                try fm.removeItem(at: url)
            } catch {
                print("[PWA] completion record could not be deleted: \(error.localizedDescription)")
            }
        }
        fsyncDirectory(root)
        return ([recordURL(root: root), tmpURL(root: root)] + legacy).allSatisfy { !fm.fileExists(atPath: $0.path) }
    }

    /// Atomic replace: write tmp, fsync it, rename over the record, fsync the directory. A failure only logs:
    /// the next cold start then takes the full pass (the safe direction).
    @discardableResult
    static func write(_ record: CashTreesPWAColdStartRecord, root: URL) -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(record) else { return false }
        let tmp = tmpURL(root: root)
        let fd = open(tmp.path, O_CREAT | O_TRUNC | O_WRONLY, 0o600)
        guard fd >= 0 else { return false }
        let written = data.withUnsafeBytes { buf -> Int in
            guard let base = buf.baseAddress else { return -1 }
            return Darwin.write(fd, base, buf.count)
        }
        let synced = fsync(fd) == 0
        close(fd)
        guard written == data.count, synced else {
            unlink(tmp.path)
            return false
        }
        guard rename(tmp.path, recordURL(root: root).path) == 0 else {
            unlink(tmp.path)
            return false
        }
        fsyncDirectory(root)
        return true
    }

    static func fsyncDirectory(_ dir: URL) {
        let fd = open(dir.path, O_RDONLY)
        guard fd >= 0 else { return }
        _ = fsync(fd)
        close(fd)
    }
}

// MARK: - Install identity

/// `silentpass_pwa/install-id.v1`: 128 random bits (32 lower-case hex), created atomically (tmp + fsync + rename with
/// RENAME_EXCL) and excluded from backup. An install-over keeps the container and the id; an uninstall drops both.
/// Not in the Keychain (it survives an uninstall) and not in UserDefaults (outside the data boundary, restored by backup).
/// Only decides whether a completion record belongs to this install; never a trust input.
nonisolated enum CashTreesPWAInstallIdentity {
    static let fileName = "install-id.v1"

    static func read(root: URL) -> String? {
        guard let data = try? Data(contentsOf: root.appendingPathComponent(fileName)),
              let s = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              s.count == 32, s.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) })
        else { return nil }
        return s
    }

    /// The existing id, or a new one. nil when it cannot be created (the caller then writes no record).
    static func currentOrCreate(root: URL) -> String? {
        if let existing = read(root: root) { return existing }
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        let id = bytes.map { String(format: "%02x", $0) }.joined()
        let final = root.appendingPathComponent(fileName)
        let tmp = root.appendingPathComponent(".\(fileName).\(UUID().uuidString).tmp")
        let fd = open(tmp.path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard fd >= 0 else { return nil }
        let data = Data(id.utf8)
        let written = data.withUnsafeBytes { buf -> Int in
            guard let base = buf.baseAddress else { return -1 }
            return Darwin.write(fd, base, buf.count)
        }
        let synced = fsync(fd) == 0
        close(fd)
        defer { unlink(tmp.path) }
        guard written == data.count, synced else { return nil }
        if renamex_np(tmp.path, final.path, UInt32(RENAME_EXCL)) != 0 {
            // Another start created it first: use that one.
            return read(root: root)
        }
        CashTreesPWAColdStartRecordIO.fsyncDirectory(root)
        var url = final
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
        return id
    }
}

// MARK: - Light identity

/// Metadata fingerprint of a directory: for each regular file (marker files excluded), one line
/// `relpath NUL size NUL mtime_ns NUL ctime_ns NUL inode`, sorted by UTF-8 bytes, SHA-256 of the whole.
/// Any symbolic link, special file (FIFO, socket, device) or read failure gives nil (treated as a miss). Reads no file content.
nonisolated enum CashTreesPWAFingerprint {
    static let excludedNames: Set<String> = [
        CashTreesPWASameVersionRule.sourceFileName, ".loaded-sha256", ".loaded-content-sha256",
    ]

    static func of(_ dir: URL) -> String? {
        let root = dir.standardizedFileURL.path
        var rootStat = stat()
        guard lstat(root, &rootStat) == 0, (rootStat.st_mode & S_IFMT) == S_IFDIR else { return nil }
        var lines: [String] = []
        var failed = false
        func walk(_ path: String, _ rel: String) {
            guard !failed, let dirp = opendir(path) else { failed = true; return }
            defer { closedir(dirp) }
            while let entry = readdir(dirp) {
                let name = withUnsafePointer(to: entry.pointee.d_name) {
                    $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
                }
                if name == "." || name == ".." { continue }
                let full = path + "/" + name
                let relPath = rel.isEmpty ? name : rel + "/" + name
                var st = stat()
                guard lstat(full, &st) == 0 else { failed = true; return }
                switch st.st_mode & S_IFMT {
                case S_IFLNK:
                    failed = true
                    return
                case S_IFDIR:
                    walk(full, relPath)
                    if failed { return }
                case S_IFREG:
                    if excludedNames.contains(name) { continue }
                    let mtime = Int64(st.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(st.st_mtimespec.tv_nsec)
                    let ctime = Int64(st.st_ctimespec.tv_sec) * 1_000_000_000 + Int64(st.st_ctimespec.tv_nsec)
                    lines.append("\(relPath)\u{0}\(st.st_size)\u{0}\(mtime)\u{0}\(ctime)\u{0}\(st.st_ino)")
                default:
                    // FIFO, socket, device or anything else that is not a regular file or a directory: unknown (a miss).
                    failed = true
                    return
                }
            }
        }
        walk(root, "")
        if failed || lines.isEmpty { return nil }
        lines.sort { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
        let text = lines.joined(separator: "\n")
        return SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Candidate selection

/// The single selection rule (pure). Inputs are cryptographic classifications only, never the record or a version claim.
nonisolated enum CashTreesPWACandidateSelector {
    enum Local: Equatable {
        /// The active tree equals the embedded build.
        case verifiedEmbedded(ver: String?)
        /// The active tree is covered by a signed OTA identity (compiled-in key, contentDigest == active digest).
        case verifiedOta(ver: String)
        /// Anything else (missing, incomplete, unsigned, unknown, mismatching).
        case unverifiable
        case none
    }

    enum Embedded: Equatable {
        /// ZIP hash equals the build identity. ver nil = the build constant cannot be parsed.
        case ok(ver: String?)
        /// Missing, hash mismatch or no identity.
        case unusable
    }

    enum Staged: Equatable {
        /// A complete staging tree covered by a valid signed OTA identity.
        case verified(ver: String)
        case none
    }

    enum Action: Equatable {
        case keepLocal(decision: String, embeddedOutcome: String)
        case installEmbedded(decision: String)
        case promoteStaged(decision: String)
        /// No trusted candidate: keep an unverifiable active if any (no record, no trust), otherwise fail the start.
        case noTrustedCandidate
        /// Verified local kept, but the embedded ZIP is unusable: no record (retry next start).
        case keepLocalNoRecord
    }

    static func newer(_ a: String?, than b: String?) -> Bool { CashTreesPWAVersion.order(a, b) == 1 }

    static func select(local: Local, embedded: Embedded, staged: Staged) -> Action {
        switch local {
        case .verifiedEmbedded:
            return .keepLocal(decision: "kept-identical", embeddedOutcome: "identical")
        case .verifiedOta(let lver):
            guard case .ok(let ever) = embedded else { return .keepLocalNoRecord }
            guard let ever else { return .keepLocal(decision: "embedded-ver-unknown", embeddedOutcome: "ver-unknown") }
            switch CashTreesPWAVersion.order(ever, lver) {
            case .some(1): return .installEmbedded(decision: "installed-newer")
            case .some(0): return .keepLocal(decision: "embedded-same-ignored", embeddedOutcome: "same-version-ignored")
            case .some(-1): return .keepLocal(decision: "embedded-older-ignored", embeddedOutcome: "older-ignored")
            default: return .keepLocal(decision: "embedded-ver-unknown", embeddedOutcome: "ver-unknown")
            }
        case .unverifiable, .none:
            let label = local == .none ? "installed-first" : "repaired-unverifiable"
            switch (embedded, staged) {
            case (.ok, .none):
                return .installEmbedded(decision: label)
            case (.unusable, .verified):
                return .promoteStaged(decision: "selected-ota-over-embedded")
            case (.ok(let ever), .verified(let sver)):
                // Same version (or an embedded version that cannot be compared): the embedded build wins.
                return newer(sver, than: ever) ? .promoteStaged(decision: "selected-ota-over-embedded") : .installEmbedded(decision: label)
            case (.unusable, .none):
                return .noTrustedCandidate
            }
        }
    }
}

// MARK: - Outcome and counters

/// What one cold start did. Counters are per call, so concurrent work elsewhere cannot blur them.
nonisolated struct CashTreesPWAColdStartOutcome: Equatable {
    enum Path: String { case fast, full }

    var path: Path = .full
    var reason = ""
    var decision = ""
    var unpackCount = 0
    var versionCompareCount = 0
    var zipReadCount = 0
    var fullDigestCount = 0
    var recordWritten = false
    var selectedOrigin = ""
    var embeddedOutcome = ""
    var network = ""
    var elapsedMs = 0.0

    var logLine: String {
        "coldstart path=\(path.rawValue) unpack=\(unpackCount) compare=\(versionCompareCount) zipRead=\(zipReadCount) "
            + "digest=\(fullDigestCount) decision=\(decision.isEmpty ? "-" : decision) origin=\(selectedOrigin.isEmpty ? "-" : selectedOrigin) "
            + "embedded=\(embeddedOutcome.isEmpty ? "-" : embeddedOutcome) network=\(network.isEmpty ? "-" : network) reason=\(reason.isEmpty ? "-" : reason) "
            + "record=\(recordWritten ? 1 : 0) ms=\(String(format: "%.2f", elapsedMs))"
    }
}
