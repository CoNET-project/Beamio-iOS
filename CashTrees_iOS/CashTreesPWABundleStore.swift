//
//  CashTreesPWABundleStore.swift
//  CashTrees_iOS
//

import Foundation
import Darwin
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
nonisolated final class CashTreesPWABundleStore {
    static let shared = CashTreesPWABundleStore()

    private let fileManager = FileManager.default
    private let lock = NSLock()

    let rootDir: URL
    let activeDir: URL
    let stagingDir: URL
    let backupDir: URL
    let otaSignedDir: URL

    private(set) var pendingVersion: String?
    /// Active-tree digests computed by this store instance (observed by tests; no behavioral effect).
    private(set) var activeTreeDigestComputations = 0
    /// Per-call outcome of the last cold start (tests and the cold-start log read it).
    private(set) var lastColdStart = CashTreesPWAColdStartOutcome()
    /// Process-local digest cache for the active tree, keyed by the metadata fingerprint. The first value in a process
    /// is always a full digest; a changed fingerprint recomputes; any change to `active/` clears it.
    private var treeDigestCache: (fingerprint: String, digest: String)?
    /// Full active-tree digests computed for bridge trust in this store (warm-up or first gate check).
    private(set) var trustDigestComputations = 0
    /// Signature checks of stored signed objects, cached by the SHA-256 of the file bytes (one Ed25519 check per file
    /// per process).
    private var signedObjectCache: [String: CashTreesPWAOtaManifestCheck] = [:]
    private(set) var signatureChecks = 0
    private var generation = 0
    /// Embedded build identity of this process (set by the cold start; trust and the daemon read it).
    private var sessionFacts: CashTreesPWAEmbeddedFacts?
    /// Owner tag of this process's partial staging directory.
    let processInstance = UUID().uuidString

    let otaVerifier: CashTreesPWAOtaVerifier
    let keyTableId: String

    private convenience init() {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            fatalError("Documents directory unavailable")
        }
        self.init(
            root: documents.appendingPathComponent("silentpass_pwa", isDirectory: true),
            otaKeys: CashTreesPWAOtaKeys.trusted,
            shellBuild: CashTreesPWAOtaVerifier.currentShellBuild
        )
    }

    /// Test seam: the same layout under an explicit root (the app uses `shared`).
    convenience init(testRootDir: URL, otaKeys: [CashTreesPWAOtaPublicKey] = [], shellBuild: Int64 = 999) {
        self.init(root: testRootDir, otaKeys: otaKeys, shellBuild: shellBuild)
    }

    private init(root: URL, otaKeys: [CashTreesPWAOtaPublicKey], shellBuild: Int64) {
        rootDir = root
        activeDir = rootDir.appendingPathComponent("active", isDirectory: true)
        stagingDir = rootDir.appendingPathComponent("staging", isDirectory: true)
        backupDir = rootDir.appendingPathComponent("backup", isDirectory: true)
        otaSignedDir = rootDir.appendingPathComponent("ota-signed", isDirectory: true)
        otaVerifier = CashTreesPWAOtaVerifier(trustedKeys: otaKeys, shellBuild: shellBuild)
        keyTableId = CashTreesPWAOtaKeys.tableId(otaKeys)
        pendingVersion = Self.readPendingVersion(from: stagingDir)
    }

    @MainActor
    func bootstrapIfNeeded() throws {
        let zip = Bundle.main.url(forResource: "SilentPassUI", withExtension: "zip")
        let facts = Self.embeddedBuildFacts()
        let build = (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String) ?? ""
        try coldStart(
            bundledZip: zip,
            facts: CashTreesPWAEmbeddedFacts(ver: facts?.ver, zipSha256: facts?.zipSha256, treeDigest: facts?.treeDigest),
            shellBuild: build
        )
        // lastColdStart carries the elapsed time (set when coldStart returns).
        CashTreesWebConsoleRelay.logNative("[PWA] \(lastColdStart.logLine)")
    }

    /// Build-time identity of the embedded ZIP (BeamioPWABuild.json, written by scripts/pwa-embed-digest.sh).
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

    /// Compatibility entry for older callers and tests (no embedded version). Prefer `coldStart`.
    func bootstrap(bundledZip zipOptional: URL?, embeddedTreeDigest: String?, embeddedZipSha256: String?) throws {
        _ = try coldStart(
            bundledZip: zipOptional,
            facts: CashTreesPWAEmbeddedFacts(ver: nil, zipSha256: embeddedZipSha256, treeDigest: embeddedTreeDigest),
            shellBuild: ""
        )
    }

    /// Cold start. Fast path: the completion record (v2), this install's identity, the embedded build identity, the
    /// selected bundle, the active fingerprint and the absence of residue all match, so the active bundle opens with no
    /// ZIP read, no unpack, no version comparison, no signature check and no full digest. Otherwise the record is deleted
    /// first and the full pass classifies the candidates and selects one.
    @discardableResult
    func coldStart(
        bundledZip zipOptional: URL?,
        facts: CashTreesPWAEmbeddedFacts,
        shellBuild: String
    ) throws -> CashTreesPWAColdStartOutcome {
        lock.lock()
        defer { lock.unlock() }
        sessionFacts = facts
        let started = Date()
        var outcome = CashTreesPWAColdStartOutcome()
        func finish() -> CashTreesPWAColdStartOutcome {
            outcome.elapsedMs = Date().timeIntervalSince(started) * 1000
            lastColdStart = outcome
            return outcome
        }
        defer { if lastColdStart != outcome { _ = finish() } }
        try fileManager.createDirectory(at: rootDir, withIntermediateDirectories: true)
        Self.excludeFromBackup(rootDir)
        let record = CashTreesPWAColdStartRecordIO.read(root: rootDir)
        let miss = fastPathMissReason(record: record, facts: facts)
        if miss == nil, let record {
            outcome.path = .fast
            outcome.decision = record.decision
            outcome.selectedOrigin = record.selected.origin
            outcome.embeddedOutcome = record.embedded.outcome
            outcome.network = record.network
            outcome.reason = "hit"
            return finish()
        }
        outcome.path = .full
        outcome.reason = miss ?? "miss"
        treeDigestCache = nil
        guard CashTreesPWAColdStartRecordIO.invalidate(root: rootDir) else {
            // Delete-before-change could not be kept: open what is there, change nothing, write nothing.
            outcome.decision = "record-not-deleted"
            if hasValidBundle(at: activeDir) { return finish() }
            throw NSError(domain: "CashTreesPWABundleStore", code: 423,
                          userInfo: [NSLocalizedDescriptionKey: "Cold-start record could not be deleted"])
        }
        try fullPass(zipOptional: zipOptional, facts: facts, shellBuild: shellBuild, outcome: &outcome)
        return finish()
    }

    /// The whole bundle root (active, staging, backup, signed objects, record, install id) stays out of iCloud and
    /// device-transfer backups: everything in it is rebuilt from the embedded ZIP or a new signed download. Set on every
    /// cold start when missing (a metadata read when already set); the flag on the directory covers its contents and
    /// does not touch the active tree, so the fast path is unaffected.
    static func excludeFromBackup(_ dir: URL) {
        var url = dir
        if (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup == true { return }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    /// nil = fast-path hit. Otherwise the miss reason for the log. Stat-level checks only (plus the install id and, for
    /// an OTA selection, the hash of the <1 KB signed object file): no ZIP, no tree content, no signature check.
    private func fastPathMissReason(record: CashTreesPWAColdStartRecord?, facts: CashTreesPWAEmbeddedFacts) -> String? {
        guard let rec = record else {
            return fileManager.fileExists(atPath: CashTreesPWAColdStartRecordIO.recordURL(root: rootDir).path) ? "parse-error" : "no-record"
        }
        guard rec.result == "complete", rec.platform == "ios", rec.variant == "ios" else { return "parse-error" }
        guard rec.ruleVersion == CashTreesPWAColdStartRecord.ruleVersion else { return "rule-changed" }
        guard let installId = CashTreesPWAInstallIdentity.read(root: rootDir) else { return "install-unknown" }
        guard rec.installId == installId else { return "install-changed" }
        guard let zip = facts.zipSha256, !zip.isEmpty, let tree = facts.treeDigest, !tree.isEmpty else { return "no-embedded-identity" }
        guard rec.embedded.zipSha256 == zip, rec.embedded.contentDigest == tree else { return "zip-changed" }
        let residue = [
            CashTreesPWAColdStartRecordIO.tmpURL(root: rootDir),
            rootDir.appendingPathComponent("bundled", isDirectory: true),
            rootDir.appendingPathComponent(CashTreesPWASameVersionRule.previousActiveName, isDirectory: true),
            recordTempURL(for: activeDir),
            activeDir.appendingPathComponent(CashTreesPWASameVersionRule.sourceTmpFileName),
        ]
        if residue.contains(where: { fileManager.fileExists(atPath: $0.path) }) { return "residue" }
        if !foreignPartials().isEmpty { return "residue" }
        guard hasValidBundle(at: activeDir) else { return "active-incomplete" }
        switch rec.selected.origin {
        case "embedded":
            guard rec.selected.contentDigest == tree else { return "selected-changed" }
        case "ota":
            guard let ota = rec.selected.ota, ota.keyTableId == keyTableId,
                  let data = try? Data(contentsOf: rootDir.appendingPathComponent(ota.signedFile)),
                  data.count <= CashTreesPWAOtaVerifier.maxSignedObjectBytes,
                  CashTreesPWASameVersionRule.sha256Hex(data) == ota.signedFileSha256
            else { return "selected-changed" }
        default:
            return "parse-error"
        }
        guard let fp = CashTreesPWAFingerprint.of(activeDir), fp == rec.activeFingerprint else { return "fingerprint-changed" }
        return nil
    }

    /// Full pass. Runs with the record already deleted.
    private func fullPass(
        zipOptional: URL?,
        facts: CashTreesPWAEmbeddedFacts,
        shellBuild: String,
        outcome: inout CashTreesPWAColdStartOutcome
    ) throws {
        let comparesBefore = CashTreesPWAVersion.compareCount
        defer { outcome.versionCompareCount = CashTreesPWAVersion.compareCount - comparesBefore }
        recoverInterruptedSwap()
        // A stale unpack target from an interrupted start is never reused; partial staging of other processes is dropped.
        try? fileManager.removeItem(at: rootDir.appendingPathComponent("bundled", isDirectory: true))
        for partial in foreignPartials() { try? fileManager.removeItem(at: partial) }
        let installId = CashTreesPWAInstallIdentity.currentOrCreate(root: rootDir)
        let activeComplete = hasValidBundle(at: activeDir)
        guard facts.hasIdentity, let eZip = facts.zipSha256, let eTree = facts.treeDigest else {
            // No embedded identity: a build defect. Keep a usable active, never record.
            outcome.decision = "no-embedded-identity"
            if activeComplete { return }
            throw NSError(domain: "CashTreesPWABundleStore", code: 404,
                          userInfo: [NSLocalizedDescriptionKey: "Embedded PWA identity (BeamioPWABuild.json) missing"])
        }

        // Classify the local active (cryptographic facts only).
        let activeTree: String? = activeComplete ? countedTreeDigest(activeDir, outcome: &outcome) : nil
        var local: CashTreesPWACandidateSelector.Local = activeComplete ? .unverifiable : .none
        var localOta: (manifest: CashTreesPWAOtaManifest, fileSha: String)?
        if let activeTree {
            if activeTree == eTree {
                local = .verifiedEmbedded(ver: facts.ver)
            } else if let ota = otaIdentityLocked(digest: activeTree, treeDir: activeDir) {
                local = .verifiedOta(ver: ota.manifest.ver)
                localOta = ota
            }
        }

        // Classify the embedded ZIP: only read when it can matter.
        var embedded: CashTreesPWACandidateSelector.Embedded = .ok(ver: CashTreesPWAVersion.parse(facts.ver) != nil ? facts.ver : nil)
        var embeddedZipVerified = false
        if case .verifiedEmbedded = local {
            // Identical: no ZIP read.
        } else {
            outcome.zipReadCount += 1
            if let zipPath = zipOptional, CashTreesPWASameVersionRule.fileSHA256(at: zipPath) == eZip {
                embeddedZipVerified = true
            } else {
                embedded = .unusable
            }
        }

        // Classify the staged OTA (signed and complete only); an untrusted staging is removed here.
        let staged = classifyStagedLocked(outcome: &outcome)
        outcome.network = staged.ota != nil ? "verified-staged" : readOtaStatusResult()

        let action = CashTreesPWACandidateSelector.select(local: local, embedded: embedded, staged: staged.selector)
        var selectedTree: String?
        var selectedOta: (manifest: CashTreesPWAOtaManifest, fileSha: String)?
        switch action {
        case .keepLocal(let decision, let embeddedOutcome):
            outcome.decision = decision
            outcome.embeddedOutcome = embeddedOutcome
            selectedTree = activeTree
            selectedOta = localOta
        case .installEmbedded(let decision):
            try installEmbedded(zipOptional: zipOptional, eZip: eZip, eTree: eTree, activeComplete: activeComplete,
                                zipAlreadyVerified: embeddedZipVerified, outcome: &outcome)
            if outcome.decision == "kept-after-embedded-failure" { return }
            outcome.decision = decision
            outcome.embeddedOutcome = "enabled"
            selectedTree = eTree
        case .promoteStaged(let decision):
            guard let s = staged.ota, let digest = staged.digest else { return }
            try promoteStagedLocked(expectedDigest: digest)
            outcome.decision = decision
            outcome.embeddedOutcome = "not-selected"
            selectedTree = digest
            selectedOta = s
        case .noTrustedCandidate:
            // No verified candidate: an unverifiable active stays (it gets no bridge trust); no record.
            outcome.decision = "no-trusted-candidate"
            if activeComplete { return }
            throw NSError(domain: "CashTreesPWABundleStore", code: 409,
                          userInfo: [NSLocalizedDescriptionKey: "No verified PWA bundle is available"])
        case .keepLocalNoRecord:
            outcome.decision = "kept-embedded-unusable"
            return
        }
        outcome.selectedOrigin = selectedOta == nil ? "embedded" : "ota"
        let selectedVer = readUpdateInfo(from: activeDir)?.ver
        reconcileStagingLocked(selectedVersion: selectedVer)
        gcSignedObjectsLocked()
        guard let tree = selectedTree, let fp = CashTreesPWAFingerprint.of(activeDir) else { return }
        // The selected tree was fully digested in this pass: seed the trust cache.
        treeDigestCache = (fp, tree)
        generation += 1
        guard let installId else { return } // identity unknown: no record (retried next start)
        let ota: CashTreesPWAColdStartRecord.Ota? = selectedOta.map {
            .init(signedFile: "ota-signed/\(tree).json", signedFileSha256: $0.fileSha, keyId: $0.manifest.keyId,
                  keyTableId: keyTableId, zipSha256: $0.manifest.sha256)
        }
        let record = CashTreesPWAColdStartRecord(
            schema: CashTreesPWAColdStartRecord.schemaV2,
            ruleVersion: CashTreesPWAColdStartRecord.ruleVersion,
            platform: "ios",
            variant: "ios",
            installId: installId,
            shellBuild: shellBuild,
            embedded: .init(zipSha256: eZip, contentDigest: eTree, ver: facts.ver, outcome: outcome.embeddedOutcome),
            selected: .init(origin: outcome.selectedOrigin, contentDigest: tree, ver: selectedVer, ota: ota, generation: generation),
            network: outcome.network,
            activeFingerprint: fp,
            decision: outcome.decision,
            result: "complete",
            completedAtUtc: ISO8601DateFormatter().string(from: Date())
        )
        if shellBuild.isEmpty { return }
        outcome.recordWritten = CashTreesPWAColdStartRecordIO.write(record, root: rootDir)
    }

    /// Verifies the embedded ZIP, unpacks it, checks its tree against the build identity and swaps it in.
    /// When the ZIP cannot be used and a complete active exists, the active is kept (no record: retried next start).
    private func installEmbedded(
        zipOptional: URL?, eZip: String, eTree: String, activeComplete: Bool, zipAlreadyVerified: Bool,
        outcome: inout CashTreesPWAColdStartOutcome
    ) throws {
        func keepOrThrow(_ message: String, code: Int) throws {
            print("[PWA] embedded install refused: \(message)")
            if activeComplete {
                outcome.decision = "kept-after-embedded-failure"
                return
            }
            throw NSError(domain: "CashTreesPWABundleStore", code: code, userInfo: [NSLocalizedDescriptionKey: message])
        }
        guard let zipPath = zipOptional else { return try keepOrThrow("SilentPassUI.zip missing from app bundle", code: 404) }
        if !zipAlreadyVerified {
            outcome.zipReadCount += 1
            guard CashTreesPWASameVersionRule.fileSHA256(at: zipPath) == eZip else {
                return try keepOrThrow("SilentPassUI.zip does not match the build identity", code: 409)
            }
        }
        let bundledDir = rootDir.appendingPathComponent("bundled", isDirectory: true)
        try? fileManager.removeItem(at: bundledDir)
        do {
            try fileManager.createDirectory(at: bundledDir, withIntermediateDirectories: true)
            outcome.unpackCount += 1
            try fileManager.unzipItem(at: zipPath, to: bundledDir)
        } catch {
            try? fileManager.removeItem(at: bundledDir)
            return try keepOrThrow("SilentPassUI.zip could not be unpacked: \(error.localizedDescription)", code: 500)
        }
        removeMacOsMetadata(from: bundledDir)
        guard hasValidBundle(at: bundledDir) else {
            try? fileManager.removeItem(at: bundledDir)
            return try keepOrThrow("Bundled SilentPassUI.zip did not contain index.html", code: 500)
        }
        guard countedTreeDigest(bundledDir, outcome: &outcome) == eTree else {
            try? fileManager.removeItem(at: bundledDir)
            return try keepOrThrow("Unpacked tree does not match the build identity", code: 409)
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
            CashTreesPWASourceRecord(source: .bundled, ver: readUpdateInfo(from: activeDir)?.ver ?? "", zipSha256: eZip, treeDigest: nil),
            at: activeDir
        )
        try? fileManager.removeItem(at: previous)
    }

    private func countedTreeDigest(_ dir: URL, outcome: inout CashTreesPWAColdStartOutcome) -> String? {
        outcome.fullDigestCount += 1
        activeTreeDigestComputations += 1
        return CashTreesPWASameVersionRule.treeDigest(at: dir, fileManager: fileManager)
    }

    // MARK: - Signed OTA identity

    private func signedObjectURL(digest: String) -> URL {
        otaSignedDir.appendingPathComponent("\(digest).json")
    }

    /// Caller holds `lock`. The signed OTA identity covering a tree: the stored signed object for `digest` verifies
    /// with a compiled-in key (v2, minShell, not revoked), its payload contentDigest equals `digest` (a full digest
    /// computed in this process), and its ver equals the tree's update.json ver. Records and version claims are never
    /// consulted. nil when anything fails.
    private func otaIdentityLocked(digest: String, treeDir: URL) -> (manifest: CashTreesPWAOtaManifest, fileSha: String)? {
        let url = signedObjectURL(digest: digest)
        guard let data = try? Data(contentsOf: url), data.count <= CashTreesPWAOtaVerifier.maxSignedObjectBytes else { return nil }
        let fileSha = CashTreesPWASameVersionRule.sha256Hex(data)
        let check: CashTreesPWAOtaManifestCheck
        if let cached = signedObjectCache[fileSha] {
            check = cached
        } else {
            signatureChecks += 1
            check = otaVerifier.verifySignedObject(data)
            signedObjectCache[fileSha] = check
        }
        guard check.verdict == .ok, let manifest = check.manifest,
              manifest.contentDigest == digest,
              readUpdateInfo(from: treeDir)?.ver == manifest.ver
        else { return nil }
        return (manifest, fileSha)
    }

    /// Caller holds `lock`. A complete staging tree covered by a valid signed identity is a candidate (S+); any other
    /// staging is removed.
    private func classifyStagedLocked(
        outcome: inout CashTreesPWAColdStartOutcome
    ) -> (selector: CashTreesPWACandidateSelector.Staged, digest: String?, ota: (manifest: CashTreesPWAOtaManifest, fileSha: String)?) {
        guard fileManager.fileExists(atPath: stagingDir.path) else { return (.none, nil, nil) }
        if hasValidBundle(at: stagingDir), let digest = countedTreeDigest(stagingDir, outcome: &outcome),
           let ota = otaIdentityLocked(digest: digest, treeDir: stagingDir) {
            return (.verified(ver: ota.manifest.ver), digest, ota)
        }
        try? fileManager.removeItem(at: stagingDir)
        pendingVersion = nil
        print("[PWA] staging dropped: no valid signed identity")
        return (.none, nil, nil)
    }

    /// Caller holds `lock`, record already deleted. Re-verifies the staging right before the move (full digest equal to
    /// `expectedDigest` and a valid signed identity for it), then moves it into place (active -> backup).
    private func promoteStagedLocked(expectedDigest: String) throws {
        guard hasValidBundle(at: stagingDir),
              let digest = CashTreesPWASameVersionRule.treeDigest(at: stagingDir, fileManager: fileManager),
              digest == expectedDigest,
              otaIdentityLocked(digest: digest, treeDir: stagingDir) != nil
        else {
            throw NSError(domain: "CashTreesPWABundleStore", code: 403,
                          userInfo: [NSLocalizedDescriptionKey: "Staged PWA changed or lost its signed identity before promotion"])
        }
        if fileManager.fileExists(atPath: backupDir.path) {
            try? fileManager.removeItem(at: backupDir)
        }
        if fileManager.fileExists(atPath: activeDir.path) {
            try fileManager.moveItem(at: activeDir, to: backupDir)
        }
        try fileManager.moveItem(at: stagingDir, to: activeDir)
        if let ota = readUpdateInfo(from: activeDir)?.ver {
            writeSourceRecord(CashTreesPWASourceRecord(source: .ota, ver: ota, zipSha256: nil, treeDigest: nil), at: activeDir)
        }
        treeDigestCache = nil
        pendingVersion = nil
    }

    /// A staged OTA that is not strictly newer than the selected bundle is removed (the staging is signed at this point).
    private func reconcileStagingLocked(selectedVersion: String?) {
        guard fileManager.fileExists(atPath: stagingDir.path) else { return }
        let staged = Self.readPendingVersion(from: stagingDir)
        if CashTreesPWAVersion.order(staged, selectedVersion) != 1 {
            try? fileManager.removeItem(at: stagingDir)
            pendingVersion = nil
            print("[PWA] staging dropped: staged=\(staged ?? "unknown") selected=\(selectedVersion ?? "unknown")")
        }
    }

    /// Keeps the signed objects referenced by the active and the staging trees plus the three newest; removes the rest.
    private func gcSignedObjectsLocked() {
        guard let names = try? fileManager.contentsOfDirectory(atPath: otaSignedDir.path) else { return }
        var keep = Set<String>()
        if let d = treeDigestCache?.digest { keep.insert("\(d).json") }
        let files = names.filter { $0.hasSuffix(".json") }.compactMap { name -> (String, Date)? in
            let url = otaSignedDir.appendingPathComponent(name)
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
            return (name, date)
        }.sorted { $0.1 > $1.1 }
        for (i, f) in files.enumerated() where i >= 3 && !keep.contains(f.0) {
            try? fileManager.removeItem(at: otaSignedDir.appendingPathComponent(f.0))
        }
        for name in names where name.hasPrefix(".") && name.hasSuffix(".tmp") {
            try? fileManager.removeItem(at: otaSignedDir.appendingPathComponent(name))
        }
    }

    private func partialName() -> String { ".staging-partial-\(processInstance)" }

    /// Partial staging directories owned by other process instances (leftovers of an interrupted download).
    private func foreignPartials() -> [URL] {
        guard let names = try? fileManager.contentsOfDirectory(atPath: rootDir.path) else { return [] }
        return names.filter { $0.hasPrefix(".staging-partial-") && $0 != partialName() }
            .map { rootDir.appendingPathComponent($0, isDirectory: true) }
    }

    /// The network check's last result (diagnostics only; never a trust or selection input).
    private func readOtaStatusResult() -> String {
        guard let data = try? Data(contentsOf: rootDir.appendingPathComponent("ota-status.v1.json")),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let result = obj["result"] as? String
        else { return "none" }
        return result
    }

    /// Writes ota-status.v1.json atomically (diagnostics only).
    func writeOtaStatus(result: String, verdict: String?, ver: String?) {
        lock.lock()
        defer { lock.unlock() }
        try? fileManager.createDirectory(at: rootDir, withIntermediateDirectories: true)
        var obj: [String: Any] = ["result": result, "checkedAtUtc": ISO8601DateFormatter().string(from: Date())]
        if let verdict { obj["verdict"] = verdict }
        if let ver { obj["ver"] = ver }
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]) else { return }
        _ = Self.atomicWrite(data, to: rootDir.appendingPathComponent("ota-status.v1.json"), dir: rootDir)
    }

    private static func atomicWrite(_ data: Data, to final: URL, dir: URL) -> Bool {
        let tmp = dir.appendingPathComponent(".\(final.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = open(tmp.path, O_CREAT | O_TRUNC | O_WRONLY, 0o600)
        guard fd >= 0 else { return false }
        let written = data.withUnsafeBytes { buf -> Int in
            guard let base = buf.baseAddress else { return -1 }
            return Darwin.write(fd, base, buf.count)
        }
        let synced = fsync(fd) == 0
        close(fd)
        guard written == data.count, synced, rename(tmp.path, final.path) == 0 else {
            unlink(tmp.path)
            return false
        }
        CashTreesPWAColdStartRecordIO.fsyncDirectory(dir)
        return true
    }

    /// Caller holds `lock`. Version of the selected verified bundle: the active when it resolves to the embedded or a
    /// signed OTA identity, otherwise the embedded build constant. Never "0.0.0" and never an unverified claim.
    private func selectedVerifiedVersionLocked() -> String? {
        let facts = sessionFacts ?? Self.embeddedBuildFacts().map {
            CashTreesPWAEmbeddedFacts(ver: $0.ver, zipSha256: $0.zipSha256, treeDigest: $0.treeDigest)
        }
        if hasValidBundle(at: activeDir), let d = cachedActiveTreeDigestLocked(digest: { CashTreesPWASameVersionRule.treeDigest(at: $0) }) {
            if d == facts?.treeDigest { return facts?.ver }
            if let ota = otaIdentityLocked(digest: d, treeDir: activeDir) { return ota.manifest.ver }
        }
        return facts?.ver
    }

    /// The daemon's reference version (see `selectedVerifiedVersionLocked`).
    func selectedVerifiedVersion() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return selectedVerifiedVersionLocked()
    }

    // MARK: - Interrupted swaps

    /// Restores an interrupted swap: if `active` is missing and `active.prev` exists, move it back; if both exist, the
    /// swap completed before the prev was dropped, so keep `active` and drop the stale prev. An OTA promotion killed
    /// between "active -> backup" and "staging -> active" leaves no complete active and a complete backup: move the
    /// backup back (the staging stays and is reconciled later).
    func recoverInterruptedSwap() {
        try? fileManager.removeItem(at: recordTempURL(for: activeDir))
        try? fileManager.removeItem(at: activeDir.appendingPathComponent(CashTreesPWASameVersionRule.sourceTmpFileName))
        let previous = rootDir.appendingPathComponent(CashTreesPWASameVersionRule.previousActiveName, isDirectory: true)
        if fileManager.fileExists(atPath: previous.path) {
            if fileManager.fileExists(atPath: activeDir.path) {
                try? fileManager.removeItem(at: previous)
            } else {
                try? fileManager.moveItem(at: previous, to: activeDir)
            }
        }
        if !hasValidBundle(at: activeDir), hasValidBundle(at: backupDir) {
            try? fileManager.removeItem(at: activeDir)
            if (try? fileManager.moveItem(at: backupDir, to: activeDir)) != nil {
                print("[PWA] interrupted OTA promotion: backup restored to active")
            }
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
            // rename(2) replaces the record atomically (no remove-then-move window).
            guard rename(tmp.path, final.path) == 0 else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
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

    /// Display version of the active bundle ("" when unreadable). Not a trust or selection input.
    func activeVersion() -> String {
        readUpdateInfo(from: activeDir)?.ver ?? ""
    }

    /// The identity the active tree resolves to: the embedded build (tree and version equal the build constants) or a
    /// signed OTA identity (signed object verified with a compiled-in key, payload contentDigest == full digest).
    /// nil when neither holds. Records, version claims and status files are never consulted.
    func activeResolvedIdentity(
        embeddedVersion: String, embeddedTree: String, digest: (URL) -> String?
    ) -> (version: String, tree: String, zipSha256: String?, origin: String)? {
        lock.lock()
        defer { lock.unlock() }
        guard hasValidBundle(at: activeDir), let d = cachedActiveTreeDigestLocked(digest: digest) else { return nil }
        let ver = readUpdateInfo(from: activeDir)?.ver
        if !embeddedTree.isEmpty, d == embeddedTree, ver == embeddedVersion {
            return (embeddedVersion, d, nil, "embedded")
        }
        if let ota = otaIdentityLocked(digest: d, treeDir: activeDir) {
            return (ota.manifest.ver, d, ota.manifest.sha256, "ota")
        }
        return nil
    }

    /// Checks the active content under the same lock used by bootstrap and OTA promotion (embedded identity only).
    func activeBundleMatches(expectedVersion: String, expectedTreeSHA256: String, digest: (URL) -> String?) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard hasValidBundle(at: activeDir), readUpdateInfo(from: activeDir)?.ver == expectedVersion,
              let actual = cachedActiveTreeDigestLocked(digest: digest)
        else { return false }
        return actual == expectedTreeSHA256
    }

    func activeTreeSHA256(digest: (URL) -> String?) -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard hasValidBundle(at: activeDir) else { return nil }
        return cachedActiveTreeDigestLocked(digest: digest)
    }

    /// Caller holds `lock`. The active fingerprint is the cache key: an unchanged fingerprint reuses the digest computed
    /// earlier in this process; a changed or unreadable fingerprint recomputes the full digest. Never seeded from the record.
    private func cachedActiveTreeDigestLocked(digest: (URL) -> String?) -> String? {
        let fp = CashTreesPWAFingerprint.of(activeDir)
        if let fp, let cached = treeDigestCache, cached.fingerprint == fp {
            return cached.digest
        }
        trustDigestComputations += 1
        guard let value = digest(activeDir) else { return nil }
        if let fp { treeDigestCache = (fp, value) } else { treeDigestCache = nil }
        return value
    }

    /// Bridge-trust warm-up after a start: one full digest (and, for an OTA tree, one signature check) in the background,
    /// before the first gate check needs it. When the tree resolves to neither the embedded build nor a signed OTA
    /// identity, the completion record is deleted so the next cold start decides again; the bridge stays closed through
    /// NativeBridgeTrust either way.
    @discardableResult
    func warmUpTrust(expectedEmbeddedTree: String, digest: (URL) -> String?) -> (digest: String?, trusted: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard hasValidBundle(at: activeDir) else { return (nil, false) }
        let value = cachedActiveTreeDigestLocked(digest: digest)
        var trusted = value != nil && value == expectedEmbeddedTree
        if !trusted, let value, otaIdentityLocked(digest: value, treeDir: activeDir) != nil { trusted = true }
        if !trusted {
            CashTreesPWAColdStartRecordIO.invalidate(root: rootDir)
            treeDigestCache = nil
            print("[PWA] trust warm-up: active tree has no trusted identity; record deleted, bridge stays closed")
        }
        return (value, trusted)
    }

    /// Compatibility wrapper (embedded identity or signed OTA identity).
    @discardableResult
    func warmUpTrustDigest(expectedTreeSHA256: String, digest: (URL) -> String?) -> String? {
        warmUpTrust(expectedEmbeddedTree: expectedTreeSHA256, digest: digest).digest
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

    /// Stages a downloaded OTA bundle whose signed manifest and ZIP bytes (size, sha256) were already verified.
    /// Unpacks outside the lock into this process's partial directory, checks the canonical form, index.html, the ZIP's
    /// own update.json ver (never rewritten) and beamio-tree-v1 == payload.contentDigest. Then, under the lock, re-reads
    /// the reference version, writes ota-signed/<digest>.json atomically and renames the partial into staging.
    func installDownloadToStaging(zip zipFile: URL, manifest: CashTreesPWAOtaManifest, signedObject: Data) throws -> CashTreesPWAOtaVerdict {
        let partial = rootDir.appendingPathComponent(partialName(), isDirectory: true)
        try? fileManager.removeItem(at: partial)
        try fileManager.createDirectory(at: rootDir, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: partial) }
        let verdict = CashTreesPWAZipCanonical.extractVerified(zip: zipFile, to: partial, expectedVer: manifest.ver,
                                                               expectedContentDigest: manifest.contentDigest)
        guard verdict == .ok, hasValidBundle(at: partial) else { return verdict == .ok ? .noncanonicalZip : verdict }

        lock.lock()
        defer { lock.unlock() }
        guard CashTreesPWAVersion.order(manifest.ver, selectedVerifiedVersionLocked()) == 1 else { return .downgrade }
        try fileManager.createDirectory(at: otaSignedDir, withIntermediateDirectories: true)
        guard Self.atomicWrite(signedObject, to: signedObjectURL(digest: manifest.contentDigest), dir: otaSignedDir) else {
            throw NSError(domain: "CashTreesPWABundleStore", code: 500,
                          userInfo: [NSLocalizedDescriptionKey: "Signed OTA object could not be written"])
        }
        try? fileManager.removeItem(at: stagingDir)
        try fileManager.moveItem(at: partial, to: stagingDir)
        CashTreesPWAColdStartRecordIO.fsyncDirectory(rootDir)
        pendingVersion = manifest.ver
        return .ok
    }

    /// Page-requested promotion of the staged OTA. The staging must resolve to a signed identity (re-verified, full
    /// digest) and be strictly newer than the selected verified bundle; the record is deleted first (refused if it cannot
    /// be). No completion record is written here: the next cold start classifies the new active and records it.
    func promoteStagingToActive() throws {
        lock.lock()
        defer { lock.unlock() }
        pendingVersion = Self.readPendingVersion(from: stagingDir)
        guard hasValidBundle(at: stagingDir) else {
            pendingVersion = nil
            throw NSError(domain: "CashTreesPWABundleStore", code: 404,
                          userInfo: [NSLocalizedDescriptionKey: "No staged PWA update"])
        }
        guard let digest = CashTreesPWASameVersionRule.treeDigest(at: stagingDir, fileManager: fileManager),
              let ota = otaIdentityLocked(digest: digest, treeDir: stagingDir)
        else {
            throw NSError(domain: "CashTreesPWABundleStore", code: 403,
                          userInfo: [NSLocalizedDescriptionKey: "Staged PWA has no valid signed identity"])
        }
        guard CashTreesPWAVersion.order(ota.manifest.ver, selectedVerifiedVersionLocked()) == 1 else {
            throw NSError(domain: "CashTreesPWABundleStore", code: 409,
                          userInfo: [NSLocalizedDescriptionKey: "Staged PWA is not strictly newer than the selected bundle"])
        }
        // Delete-before-change: the completion record goes before the active directory moves.
        treeDigestCache = nil
        guard CashTreesPWAColdStartRecordIO.invalidate(root: rootDir) else {
            throw NSError(domain: "CashTreesPWABundleStore", code: 423,
                          userInfo: [NSLocalizedDescriptionKey: "Cold-start record could not be deleted; promotion refused"])
        }
        try promoteStagedLocked(expectedDigest: digest)
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

    /// Strict comparison: three numeric segments only; an unknown version on either side is never newer.
    static func isSemverNewer(oldVer: String, newVer: String) -> Bool {
        CashTreesPWAVersion.isStrictlyNewer(old: oldVer, new: newVer) == true
    }
}
