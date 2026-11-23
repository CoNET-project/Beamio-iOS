import Foundation
import Testing
@testable import CashTrees_iOS

/// The passcode reply target judged by the runtime trust decision (`NativeBridgeTrust.bundleTrusted`, the same function that
/// `currentBundleIsTrusted` calls with the real evidence). The evidence (embedded zip, active bundle) is a property of the installed
/// app and of the simulator's state, so the test supplies it: all true for the positive control, and one axis at a time for each
/// negative. A negative therefore fails for its own axis. `currentBundleIsTrusted` depends on that state and is not asserted here.
@Suite struct PasscodeTrustEndToEndTests {
    private let tree = NativeBridgeTrust.expectedActiveTreeSHA256
    private let localDocument = "cashtrees-local://localhost/index.html"

    /// The runtime decision with the evidence given. Every evidence value is true unless a case changes it.
    private func gate(
        isMainFrame: Bool = true,
        scheme: String = CashTreesPWAScheme.scheme,
        host: String = CashTreesPWAScheme.host,
        port: Int = 0,
        document: String? = nil,
        committed: String? = nil,
        generation: Bool = true,
        zip: Bool = true,
        bundle: Bool = true
    ) -> Bool {
        let frameURL = URL(string: document ?? localDocument)
        let committedURL = URL(string: committed ?? document ?? localDocument)
        return NativeBridgeTrust.bundleTrusted(
            isMainFrame: isMainFrame,
            scheme: scheme,
            host: host,
            port: port,
            frameDocumentURL: frameURL,
            committedDocumentURL: committedURL,
            generationMatches: generation,
            zipMatches: zip,
            activeBundleMatches: bundle
        )
    }

    // MARK: Positive control

    @Test func theLocalMainFrameWithAllEvidenceIsTrusted() {
        #expect(gate(), "the positive control: every axis and every piece of evidence agree")
    }

    // MARK: Each axis refuses on its own (all other evidence true)

    @Test func aSubFrameIsRefusedByTheFrameAxis() {
        #expect(!gate(isMainFrame: false), "the frame axis alone refuses a sub-frame")
    }

    @Test func aRemoteOriginIsRefusedByTheSchemeAndHostAxes() {
        #expect(!gate(scheme: "https", host: "beamio.app", document: "https://beamio.app/"))
        #expect(!gate(scheme: "https", host: CashTreesPWAScheme.host, document: "https://localhost/index.html"),
                "the same host under another scheme is refused")
    }

    @Test func similarDomainsAreRefusedByTheHostAxis() {
        let similar = [
            "cashtrees-local://localhost.evil/index.html",
            "cashtrees-local://evil.localhost/index.html",
            "cashtrees-local://localhost./index.html",
        ]
        for document in similar {
            #expect(!gate(host: URL(string: document)?.host ?? "", document: document), "\(document) is refused by the host axis")
        }
    }

    @Test func aNonZeroPortIsRefusedByThePortAxis() {
        #expect(!gate(port: 8443), "the port axis alone refuses a non-default port")
    }

    @Test func aDocumentThatChangedSinceTheNavigationIsRefused() {
        #expect(!gate(document: localDocument, committed: "cashtrees-local://localhost/other.html"),
                "the frame URL must equal the committed document URL")
    }

    // MARK: Each piece of evidence refuses on its own

    @Test func aStaleGenerationIsRefused() {
        #expect(!gate(generation: false))
    }

    @Test func aMissingOrChangedEmbeddedZipIsRefused() {
        #expect(!gate(zip: false))
    }

    @Test func aBundleThatIsNotTheActiveOneIsRefused() {
        #expect(!gate(bundle: false))
    }

    // MARK: Outlet, fed by the runtime decision

    @Test func theOutletTargetsOnlyATrustedDecision() {
        let store = PasscodeReplyProxyStore()
        let trusted = PasscodeEventOutlet.proxy(trusted: gate(), scheme: CashTreesPWAScheme.scheme, host: CashTreesPWAScheme.host,
                                                port: 0, documentURL: localDocument, documentTreeSHA256: tree)
        store.record(trusted)
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: trusted) == .deliver)

        let refused = PasscodeEventOutlet.proxy(trusted: gate(isMainFrame: false), scheme: CashTreesPWAScheme.scheme,
                                                host: CashTreesPWAScheme.host, port: 0, documentURL: localDocument, documentTreeSHA256: tree)
        store.record(refused)
        #expect(store.current() == trusted, "a refused request does not replace the trusted target")
    }
}
