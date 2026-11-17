import Testing
@testable import CashTrees_iOS

/// The shell sets the chat SDK's apiBaseUrl to beamio.ca on every forwarded `init` (owner ruling 2026-11-17).
struct ChatApiBaseOverrideTests {
    @Test func initWithLegacyHostIsRewrittenToBeamioCa() {
        let out = ChatApiBaseOverride.apply(["type": "init", "reqId": 1,
                                             "payload": ["apiBaseUrl": "https://beamio.app/api", "chainId": 224422]])
        let payload = out["payload"] as? [String: Any]
        #expect(payload?["apiBaseUrl"] as? String == "https://beamio.ca/api")
        #expect(payload?["chainId"] as? Int == 224422, "other payload fields are kept")
        #expect(out["reqId"] as? Int == 1)
    }

    @Test func initWithoutApiBaseUrlGetsBeamioCa() {
        let out = ChatApiBaseOverride.apply(["type": "init", "reqId": 2, "payload": ["chainId": 224422]])
        #expect((out["payload"] as? [String: Any])?["apiBaseUrl"] as? String == "https://beamio.ca/api")
    }

    @Test func otherCommandsAreUnchanged() {
        let cmd: [String: Any] = ["type": "walletStatus", "reqId": 3, "payload": ["apiBaseUrl": "https://beamio.app/api"]]
        let out = ChatApiBaseOverride.apply(cmd)
        #expect((out["payload"] as? [String: Any])?["apiBaseUrl"] as? String == "https://beamio.app/api")
    }

    @Test func initWithoutPayloadIsForwardedAsIs() {
        let out = ChatApiBaseOverride.apply(["type": "init", "reqId": 4])
        #expect(out["payload"] == nil)
    }
}
