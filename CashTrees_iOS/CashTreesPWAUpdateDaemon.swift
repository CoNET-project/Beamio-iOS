//
//  CashTreesPWAUpdateDaemon.swift
//  CashTrees_iOS
//

import Foundation

/// Polls `https://beamio.ca/app/update.json`, downloads newer bundles into `staging/`.
/// Redirects are followed only on the same OTA host over https (`BeamioOutboundHosts.otaHosts`).
@MainActor
final class CashTreesPWAUpdateDaemon {
    static let shared = CashTreesPWAUpdateDaemon(bundleStore: CashTreesPWABundleStore.shared)

    static let checkIntervalSeconds: TimeInterval = 15 * 60

    private let bundleStore: CashTreesPWABundleStore
    private let session: URLSession
    private var scheduleTask: Task<Void, Never>?
    private var checkInFlight = false

    private init(bundleStore: CashTreesPWABundleStore) {
        self.bundleStore = bundleStore
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 120
        self.session = URLSession(
            configuration: config,
            delegate: BeamioOutboundRedirectGuard(hosts: BeamioOutboundHosts.otaHosts),
            delegateQueue: nil
        )
    }

    func start() {
        guard scheduleTask == nil else { return }
        scheduleTask = Task { [weak self] in
            await self?.runLoop()
        }
    }

    func stop() {
        scheduleTask?.cancel()
        scheduleTask = nil
    }

    /// Immediate check (foreground resume).
    func checkNow() async {
        await performCheck()
    }

    private func runLoop() async {
        await performCheck()
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: UInt64(Self.checkIntervalSeconds * 1_000_000_000))
            if Task.isCancelled { break }
            await performCheck()
        }
    }

    /// Signed OTA check (manifest v2, enforced). Trust comes only from a signature by a compiled-in key; the payload's
    /// size, sha256 and contentDigest must all hold. The reference version is the selected verified bundle (never an
    /// unverified claim or "0.0.0"). With an empty key table there is no OTA: no request is made.
    private func performCheck() async {
        guard !checkInFlight else { return }
        checkInFlight = true
        defer { checkInFlight = false }
        let keys = CashTreesPWAOtaKeys.trusted
        guard !keys.isEmpty, let endpoint = Self.endpoint() else { return }
        let verifier = CashTreesPWAOtaVerifier(trustedKeys: keys, shellBuild: CashTreesPWAOtaVerifier.currentShellBuild)
        let store = bundleStore
        let session = self.session
        let reference = await Task.detached { store.selectedVerifiedVersion() }.value
        let data: Data
        do {
            data = try await Self.fetch(endpoint.manifest, session: session, allowed: endpoint.allowed)
        } catch {
            store.writeOtaStatus(result: "network-error", verdict: nil, ver: nil)
            print("⚠️ CashTreesPWAUpdateDaemon: manifest fetch failed: \(error.localizedDescription)")
            return
        }
        let check = verifier.verifyManifest(data, referenceVersion: reference)
        guard check.verdict == .ok, let manifest = check.manifest, let signedObject = check.signedObject else {
            let result = check.verdict == .downgrade ? "up-to-date" : check.verdict.statusClass
            store.writeOtaStatus(result: result, verdict: check.verdict.rawValue, ver: check.manifest?.ver)
            if check.verdict != .downgrade {
                print("⚠️ CashTreesPWAUpdateDaemon: manifest refused verdict=\(check.verdict.rawValue)")
            }
            return
        }
        // Shell limit on the ZIP itself: refused before any download.
        guard manifest.size <= CashTreesPWAOtaVerifier.maxZipBytes else {
            store.writeOtaStatus(result: CashTreesPWAOtaVerdict.tooLarge.statusClass, verdict: CashTreesPWAOtaVerdict.tooLarge.rawValue,
                                 ver: manifest.ver)
            return
        }
        if let pending = store.pendingUpdateVersion(), pending == manifest.ver {
            postUpdateAvailable(current: store.activeVersion(), pending: manifest.ver)
            return
        }
        let zip: URL
        do {
            zip = try await Self.download(endpoint.bundleBase.appendingPathComponent(manifest.filename), session: session,
                                          allowed: endpoint.allowed, maxBytes: manifest.size)
        } catch CashTreesPWADownloadError.exceededDeclaredSize {
            store.writeOtaStatus(result: CashTreesPWAOtaVerdict.sizeMismatch.statusClass,
                                 verdict: CashTreesPWAOtaVerdict.sizeMismatch.rawValue, ver: manifest.ver)
            return
        } catch {
            store.writeOtaStatus(result: "network-error", verdict: nil, ver: manifest.ver)
            print("⚠️ CashTreesPWAUpdateDaemon: bundle download failed: \(error.localizedDescription)")
            return
        }
        defer { try? FileManager.default.removeItem(at: zip) }
        let integrity = verifier.verifyBundle(manifest, zip: zip)
        guard integrity == .ok else {
            store.writeOtaStatus(result: integrity.statusClass, verdict: integrity.rawValue, ver: manifest.ver)
            print("⚠️ CashTreesPWAUpdateDaemon: bundle refused verdict=\(integrity.rawValue)")
            return
        }
        let staged = await Task.detached { () -> CashTreesPWAOtaVerdict in
            (try? store.installDownloadToStaging(zip: zip, manifest: manifest, signedObject: signedObject)) ?? .contentMismatch
        }.value
        let result = staged == .downgrade ? "up-to-date" : staged.statusClass
        store.writeOtaStatus(result: result, verdict: staged.rawValue, ver: manifest.ver)
        guard staged == .ok else {
            print("⚠️ CashTreesPWAUpdateDaemon: staging refused verdict=\(staged.rawValue)")
            return
        }
        postUpdateAvailable(current: store.activeVersion(), pending: manifest.ver)
    }

    /// The manifest URL, the bundle base and the URL check. Production: https on the OTA host allowlist. A build compiled
    /// with BEAMIO_QA_OTA may point at a loopback stub from its own Info.plist; no other build can.
    private static func endpoint() -> (manifest: URL, bundleBase: URL, allowed: (URL) -> Bool)? {
        #if BEAMIO_QA_OTA
        if let qa = CashTreesPWAOtaQA.manifestURL {
            return (qa, qa.deletingLastPathComponent(), { $0.scheme == "http" && $0.host == "127.0.0.1" && $0.port == qa.port })
        }
        #endif
        return (CashTreesPWAScheme.remoteUpdateManifestURL, CashTreesPWAScheme.remoteBundleBaseURL,
                { BeamioOutboundHosts.allows($0, hosts: BeamioOutboundHosts.otaHosts) })
    }

    nonisolated private static func fetch(_ url: URL, session: URLSession, allowed: (URL) -> Bool) async throws -> Data {
        guard allowed(url) else { throw URLError(.unsupportedURL) }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        return data
    }

    /// Downloads to a temporary file outside silentpass_pwa/ (the caller removes it). Streams the body and stops as
    /// soon as more than `maxBytes` (the signed payload.size) arrive.
    nonisolated private static func download(_ url: URL, session: URLSession, allowed: (URL) -> Bool, maxBytes: Int64) async throws -> URL {
        // The filename comes from the signed manifest: check the final URL before the request, not only on redirect.
        guard allowed(url) else { throw URLError(.unsupportedURL) }
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
        let fm = FileManager.default
        let out = fm.temporaryDirectory.appendingPathComponent("silentpass_ota_\(UUID().uuidString).zip")
        guard fm.createFile(atPath: out.path, contents: nil), let handle = try? FileHandle(forWritingTo: out) else {
            throw URLError(.cannotCreateFile)
        }
        do {
            try await CashTreesPWABoundedWriter.copy(bytes, to: handle, maxBytes: maxBytes)
            try handle.close()
        } catch {
            try? handle.close()
            try? fm.removeItem(at: out)
            throw error
        }
        return out
    }

    private func postUpdateAvailable(current: String, pending: String) {
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

nonisolated enum CashTreesPWADownloadError: Error, Equatable {
    case exceededDeclaredSize
}

/// Copies a byte stream to a file and aborts as soon as the count passes `maxBytes`.
nonisolated enum CashTreesPWABoundedWriter {
    static func copy<S: AsyncSequence>(_ bytes: S, to handle: FileHandle, maxBytes: Int64) async throws where S.Element == UInt8 {
        var buffer = [UInt8]()
        buffer.reserveCapacity(64 * 1024)
        var total: Int64 = 0
        for try await byte in bytes {
            total += 1
            if total > maxBytes { throw CashTreesPWADownloadError.exceededDeclaredSize }
            buffer.append(byte)
            if buffer.count >= 64 * 1024 {
                try handle.write(contentsOf: buffer)
                buffer.removeAll(keepingCapacity: true)
            }
        }
        if !buffer.isEmpty { try handle.write(contentsOf: buffer) }
    }
}
