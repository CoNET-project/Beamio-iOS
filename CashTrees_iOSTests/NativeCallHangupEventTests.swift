import Foundation
import Testing
@testable import CashTrees_iOS

// v66 §73: nativeCallHangup is a page event (event whitelist), never a command; the payload is {type, callId, sessionId, reason, at}.
@Suite(.serialized)
struct NativeCallHangupEventTests {
    @Test func payloadCarriesTheFiveFields() {
        let p = NativeCallHangupEvent.payload(callId: "call-0001", sessionId: "sess-0001", atMs: 1_800_000_000_000)
        #expect(p["type"] as? String == "nativeCallHangup")
        #expect(p["callId"] as? String == "call-0001")
        #expect(p["sessionId"] as? String == "sess-0001")
        #expect(p["reason"] as? String == "local_hangup")
        #expect(p["at"] as? Int64 == 1_800_000_000_000)
        #expect(p.count == 5)
    }

    @Test func nativeCallHangupIsAnEventNotACommand() {
        #expect(PasscodeEventOutlet.eventTypes.contains("nativeCallHangup"))
        #expect(PasscodeCommandWhitelist.fieldsByCommand["nativeCallHangup"] == nil)
    }
}
