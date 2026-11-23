import Foundation
import Testing
@testable import ConetChatSDK

/// Test support for suites that run against the chat SDK's current behaviour.
enum TestSupportSdkState {
    /// The SDK's verification host (a hidden WKWebView with ethers/openpgp) must be ready before a test verifies a signature with it.
    /// In a full parallel run each simulator clone boots its own host and can miss a short first-call timeout; the SDK's test API
    /// waits for readiness (BeamioOpenPgpHost.awaitHostReadyForTests, "a suite that depends on the host calls this first").
    /// The host's own diagnostic lines are collected from the first call on (HostDiagnostics), for the intermittent-failure evidence.
    @MainActor
    static func requireVerificationHost(timeoutSeconds: TimeInterval = 90) async -> Bool {
        HostDiagnostics.shared.startIfNeeded()
        let readiness = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: timeoutSeconds)
        if !readiness.ready {
            Issue.record(Comment(rawValue: "SDK verification host not ready: " + readiness.reason + "\n" + HostDiagnostics.shared.issueText(nil)))
        }
        return readiness.ready
    }

    /// A positive host-dependent check failed (nil or false where the sample must verify). Records one Issue with the error of the
    /// failed call when the caller has it, otherwise with the error of one direct probe verification of a known public vector made now,
    /// and the last 40 host diagnostic lines (times and states only; no content, keys, signatures or addresses).
    @MainActor
    static func recordHostFailure(_ context: String, error: Error? = nil) async {
        var err = error
        if err == nil { err = await probeVerification() }
        Issue.record(Comment(rawValue: "[\(context)] " + HostDiagnostics.shared.issueText(err)))
    }

    /// Public test vector (voice_call_offer_v1 rev2, VoiceCallOfferVectorTests): only its error, if any, is kept.
    private static let probeText = "CoNET voice_call_offer_v3\ncallId:vt-call-0001\nsessionId:vt-session-0001\nto:0x000000000000000000000000000000000000dead\ncreatedAt:1795217195851\nexpiresAt:1795218095851\ntimestamp:1795217195851\ncodec:audio/pcm;rate=16000\ncallerPgp:VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==\ncallerRoute:VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ"
    private static let probeSignature = "0xf814f04f44d3342c013041364877442c7f0de864e092ca16c72dd30a4531422328b05dc310274b8e05c23e247c3437d912db10eb2af05a11c1b2899375a51d8c1c"

    @MainActor
    private static func probeVerification() async -> Error? {
        await withCheckedContinuation { (cont: CheckedContinuation<Error?, Never>) in
            BeamioOpenPgpHost.shared.verifyMessage(text: probeText, signature: probeSignature) { result in
                if case .failure(let e) = result { cont.resume(returning: e) } else { cont.resume(returning: nil) }
            }
        }
    }
}

/// Collects BeamioOpenPgpHost.diagnostics lines (boot start, host ready, boot timeout, boot retry, watchdog, host reset, torn down, call gave up)
/// with a relative time, and forwards each line to the sink that was set before. Small copy of the SDK test target's
/// OpenPgpHostDiagnosticsRecorder (chat SDK), which the shell test target cannot import.
final class HostDiagnostics: @unchecked Sendable {
    static let shared = HostDiagnostics()
    private let lock = NSLock()
    private var storage: [String] = []
    private var started = Date()
    private var running = false

    func startIfNeeded() {
        lock.lock(); defer { lock.unlock() }
        guard !running else { return }
        running = true
        started = Date()
        let previous = BeamioOpenPgpHost.diagnostics
        BeamioOpenPgpHost.diagnostics = { [weak self] line in
            if let self {
                self.lock.lock()
                self.storage.append(String(format: "+%6.2fs ", Date().timeIntervalSince(self.started)) + line)
                if self.storage.count > 400 { self.storage.removeFirst(self.storage.count - 400) }
                self.lock.unlock()
            }
            previous?(line)
        }
    }

    var lines: [String] { lock.lock(); defer { lock.unlock() }; return storage }

    /// The failure class of a host call error, from its code (-1 boot timeout, -7 watchdog, -8 torn down, -3 not ready).
    static func describe(_ error: Error) -> String {
        let ns = error as NSError
        guard ns.domain == "BeamioOpenPgp" else { return "other(\(ns.domain) \(ns.code))" }
        let unavailable = BeamioOpenPgpHost.isHostUnavailable(error) ? " unavailable" : ""
        switch ns.code {
        case -1: return "BeamioOpenPgp -1 boot timeout\(unavailable)"
        case -2: return "BeamioOpenPgp -2 scripts missing"
        case -3: return "BeamioOpenPgp -3 not ready"
        case -7: return "BeamioOpenPgp -7 call stuck (watchdog)\(unavailable)"
        case -8: return "BeamioOpenPgp -8 torn down (lock, logout or account switch)"
        default: return "BeamioOpenPgp \(ns.code)"
        }
    }

    func issueText(_ error: Error?, limit: Int = 40) -> String {
        let head = error.map { Self.describe($0) } ?? "no host error (probe verified)"
        let tail = lines.suffix(limit)
        return "host: \(head); diag lines \(tail.count):\n" + tail.joined(separator: "\n")
    }
}
