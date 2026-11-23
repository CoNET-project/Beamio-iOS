import Foundation
import Testing
@testable import CashTrees_iOS

/// The passcode event outlet (frozen protocol v1, section one, item 4): only the document of the last trusted reply receives
/// passcode events. The trust axis is the pure `NativeBridgeTrust.isTrusted` (frame, scheme, host, port, versions); the
/// full runtime gate adds the bundle identity on the device. Synthetic inputs only.
@Suite struct PasscodeEventOutletTests {
    private let localHost = CashTreesPWAScheme.host
    private let localScheme = CashTreesPWAScheme.scheme
    private let localDocument = "cashtrees-local://localhost/index.html"
    private let tree = NativeBridgeTrust.expectedActiveTreeSHA256

    /// The trust axis for one request: the same constants the runtime gate compares, with only the origin varied.
    private func trusted(isMainFrame: Bool = true, scheme: String? = nil, host: String? = nil, port: Int = 0) -> Bool {
        NativeBridgeTrust.isTrusted(
            isMainFrame: isMainFrame,
            scheme: scheme ?? localScheme,
            host: host ?? localHost,
            port: port,
            activeVersion: NativeBridgeTrust.expectedPwaVersion,
            embeddedZipSHA256: NativeBridgeTrust.expectedEmbeddedZipSHA256,
            activeTreeSHA256: tree
        )
    }

    private func proxy(
        isMainFrame: Bool = true,
        scheme: String? = nil,
        host: String? = nil,
        port: Int = 0,
        document: String? = nil,
        treeSHA: String? = nil
    ) -> PasscodeReplyProxy? {
        PasscodeEventOutlet.proxy(
            trusted: trusted(isMainFrame: isMainFrame, scheme: scheme, host: host, port: port),
            scheme: scheme ?? localScheme,
            host: host ?? localHost,
            port: port,
            documentURL: document ?? localDocument,
            documentTreeSHA256: treeSHA ?? tree
        )
    }

    @Test func aTrustedMainFrameRecordsItsProxyAndReceivesEvents() {
        let store = PasscodeReplyProxyStore()
        let trustedProxy = proxy()
        #expect(trustedProxy != nil, "the local main frame passes the trust axis")
        store.record(trustedProxy)
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: proxy()) == .deliver)
    }

    @Test func noTrustedReplyYetMeansNoEventTarget() {
        let store = PasscodeReplyProxyStore()
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: proxy()) == .noEventTarget)
    }

    @Test func anIframeRequestIsNotTrustedAndRecordsNothing() {
        let store = PasscodeReplyProxyStore()
        store.record(proxy(isMainFrame: false))
        #expect(store.current() == nil, "a sub-frame request never becomes the reply target")
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: proxy()) == .noEventTarget)
    }

    @Test func aRemoteOriginRequestIsNotTrustedAndRecordsNothing() {
        let store = PasscodeReplyProxyStore()
        store.record(proxy(scheme: "https", host: "beamio.app", document: "https://beamio.app/"))
        #expect(store.current() == nil, "a remote origin never becomes the reply target")
    }

    @Test func similarDomainsAreNotTrusted() {
        let similar: [(scheme: String?, host: String?, port: Int)] = [
            (nil, "localhost.evil", 0),
            (nil, "evil.localhost", 0),
            (nil, "localhost.", 0),
            (nil, "localhost", 8443),
            ("cashtrees-locale", nil, 0),
            ("https", "localhost", 0),
        ]
        for candidate in similar {
            #expect(proxy(scheme: candidate.scheme, host: candidate.host, port: candidate.port) == nil,
                    "\(candidate.scheme ?? localScheme)://\(candidate.host ?? localHost):\(candidate.port) is not the local bundle")
        }
    }

    @Test func anUntrustedRequestDoesNotOverwriteTheLastTrustedProxy() {
        let store = PasscodeReplyProxyStore()
        store.record(proxy())
        store.record(proxy(isMainFrame: false))
        store.record(proxy(scheme: "https", host: "beamio.app", document: "https://beamio.app/"))
        #expect(store.current() == proxy(), "the trusted proxy is kept")
    }

    @Test func navigatingToARemotePageStopsDelivery() {
        let store = PasscodeReplyProxyStore()
        store.record(proxy())
        // The page is now remote: its current proxy is nil because the trust gate fails for it.
        let remoteNow = proxy(scheme: "https", host: "beamio.app", document: "https://beamio.app/")
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: remoteNow) == .mismatch)
    }

    @Test func aChangedDocumentTreeStopsDelivery() {
        let store = PasscodeReplyProxyStore()
        store.record(proxy())
        let changed = proxy(treeSHA: String(repeating: "0", count: 64))
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: changed) == .mismatch)
    }

    @Test func aDifferentDocumentPathStopsDelivery() {
        let store = PasscodeReplyProxyStore()
        store.record(proxy())
        let otherPath = proxy(document: "cashtrees-local://localhost/other.html")
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: otherPath) == .mismatch)
    }

    @Test func resettingTheChannelClearsTheTarget() {
        let store = PasscodeReplyProxyStore()
        store.record(proxy())
        store.reset()
        #expect(store.current() == nil)
        #expect(PasscodeEventOutlet.decide(recorded: store.current(), current: proxy()) == .noEventTarget)
    }

    @Test func onlyPasscodeEventsAreRoutedThroughTheOutlet() {
        let passcodeState: [String: Any] = ["action": "chatModuleEvent", "event": ["type": "passcodeState", "set": true]]
        let repairRequest: [String: Any] = ["action": "chatModuleEvent", "event": ["type": "nativeRepairRequest", "reqId": 7_500_000_000_000]]
        let repairResult: [String: Any] = ["action": "chatModuleEvent", "event": ["type": "nativeRepairResult", "ok": true]]
        let ack: [String: Any] = ["action": "chatModuleEvent", "event": ["type": "ack", "ok": true]]
        let pushToken: [String: Any] = ["action": "pushDeviceToken", "platform": "ios"]
        #expect(PasscodeEventOutlet.isPasscodeEvent(passcodeState))
        #expect(PasscodeEventOutlet.isPasscodeEvent(repairRequest))
        #expect(PasscodeEventOutlet.isPasscodeEvent(repairResult))
        #expect(!PasscodeEventOutlet.isPasscodeEvent(ack), "an ack keeps its existing path")
        #expect(!PasscodeEventOutlet.isPasscodeEvent(pushToken), "push tokens keep their existing path")
    }

    @Test func theLogLineCarriesTypeAndReqIdOnly() {
        let payload: [String: Any] = [
            "action": "chatModuleEvent",
            "event": ["type": "nativeRepairRequest", "reqId": 7_500_000_000_001, "eoa": "0x1111111111111111111111111111111111111111", "phrase": "secret words"],
        ]
        let line = PasscodeEventOutlet.logFields(payload)
        #expect(line == "type=nativeRepairRequest reqId=7500000000001")
        #expect(!line.contains("0x1111"), "no account value in the log")
        #expect(!line.contains("secret"), "no credential value in the log")
    }
}
