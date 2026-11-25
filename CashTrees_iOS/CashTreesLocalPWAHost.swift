//
//  CashTreesLocalPWAHost.swift
//  CashTrees_iOS
//
//  Bootstraps bundled SilentPassUI → Documents/active → custom scheme handler (no HTTP server).
//

import Combine
import Foundation

@MainActor
final class CashTreesLocalPWAHost: ObservableObject {
    static let shared = CashTreesLocalPWAHost()

    let schemeHandler = CashTreesLocalSchemeHandler()

    @Published private(set) var isReady = false
    @Published private(set) var lastError: String?
    @Published private(set) var errorKind: CashTreesStartErrorKind = .startFailed

    var entryURL: URL { CashTreesPWAScheme.entryURL }

    /// Deep-link / recovery base (directory root, not index.html).
    var baseURL: URL {
        URL(string: "\(CashTreesPWAScheme.scheme)://\(CashTreesPWAScheme.host)/")!
    }

    private let bundleStore = CashTreesPWABundleStore.shared
    private var startTask: Task<Void, Never>?

    private init() {}

    func startIfNeeded() {
        guard startTask == nil else { return }
        startTask = Task { [weak self] in
            await self?.boot()
        }
    }

    func activeVersion() -> String {
        bundleStore.activeVersion()
    }

    func pendingUpdateVersion() -> String? {
        bundleStore.pendingUpdateVersion()
    }

    /// Foreground resume: opportunistic remote check (daemon also polls every 15 min).
    func refreshOnForeground() async {
        await CashTreesPWAUpdateDaemon.shared.checkNow()
        notifyPendingUpdateIfNeeded()
    }

    /// Swap Documents `silentpass_pwa/active` only. Wallet IndexedDB stays in
    /// `WKWebsiteDataStore.default()` (`cashtrees-local://localhost`) across OTA.
    func applyPendingUpdate() async -> Bool {
        guard bundleStore.hasPendingUpdate() else {
            lastError = "No staged update"
            return false
        }
        await schemeHandler.waitForInFlightTasks()
        do {
            try bundleStore.promoteStagingToActive()
            lastError = nil
            return true
        } catch {
            lastError = error.localizedDescription
            print("❌ CashTreesLocalPWAHost applyPendingUpdate: \(error.localizedDescription)")
            return false
        }
    }

    /// The background content check found an active tree that is not the embedded build (silent damage). The bridge is
    /// already closed by NativeBridgeTrust; the record was deleted. Take the page down and show the retry control: a retry
    /// runs the full pass, which repairs from the embedded build.
    func contentCheckFailed() {
        isReady = false
        startTask = nil
        errorKind = .contentCheckFailed
        lastError = "content-check-failed"
    }

    /// After a failed start the error is shown with a retry control; this runs the start again.
    func retryStart() {
        guard !isReady else { return }
        startTask?.cancel()
        startTask = nil
        lastError = nil
        startIfNeeded()
    }

    private func boot() async {
        do {
            try bundleStore.bootstrapIfNeeded()
            isReady = true
            lastError = nil
            scheduleTrustWarmUp()
            CashTreesPWAUpdateDaemon.shared.start()
            notifyPendingUpdateIfNeeded()
        } catch {
            errorKind = .startFailed
            lastError = error.localizedDescription
            // Allow a retry (startIfNeeded refuses while startTask is set).
            startTask = nil
            print("❌ CashTreesLocalPWAHost boot failed: \(error.localizedDescription)")
            CashTreesWebConsoleRelay.logNative("[PWA] coldstart failed: \(error.localizedDescription)")
        }
    }

    /// One full active-tree digest (and the one-per-process embedded ZIP hash) off the main thread, so the
    /// first gate check finds it cached. Trust is still decided only by NativeBridgeTrust against BeamioPWABuild.json.
    private func scheduleTrustWarmUp() {
        let store = bundleStore
        let expected = NativeBridgeTrust.expectedActiveTreeSHA256
        Task.detached(priority: .utility) {
            let started = Date()
            let result = store.warmUpTrust(expectedEmbeddedTree: expected) { CashTreesPWASameVersionRule.treeDigest(at: $0) }
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            let matched = result.trusted
            let line = "[PWA] trust warm-up match=\(matched ? 1 : 0) digests=\(store.trustDigestComputations) ms=\(ms)"
            await MainActor.run {
                CashTreesWebConsoleRelay.logNative(line)
                if !matched { CashTreesLocalPWAHost.shared.contentCheckFailed() }
            }
        }
    }

    private func notifyPendingUpdateIfNeeded() {
        guard let pending = bundleStore.pendingUpdateVersion() else { return }
        let current = bundleStore.activeVersion()
        NotificationCenter.default.post(
            name: .cashTreesEmbeddedPwaUpdateAvailable,
            object: nil,
            userInfo: [
                "currentVer": current,
                "pendingVer": pending,
            ]
        )
    }
}
