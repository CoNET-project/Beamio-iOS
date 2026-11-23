import Foundation
import Testing
@testable import CashTrees_iOS

/// The native field whitelist of the passcode commands (frozen protocol v1, section one, item 6). Synthetic values only.
@Suite struct PasscodeCommandWhitelistTests {
    private let eoa = "0x1111111111111111111111111111111111111111"

    @Test func provisionWithItsFieldsPasses() {
        let command: [String: Any] = ["type": "passcodeProvision", "reqId": 7_000_000_000_001, "eoa": eoa,
                                      "phrase": "synthetic phrase", "passcode": "123456"]
        #expect(PasscodeCommandWhitelist.refusal(for: command) == nil)
    }

    @Test func unlockRefusesThePhraseField() {
        let command: [String: Any] = ["type": "passcodeUnlock", "reqId": 7_000_000_000_002, "eoa": eoa,
                                      "passcode": "123456", "phrase": "synthetic phrase"]
        #expect(PasscodeCommandWhitelist.refusal(for: command) == "bad_request",
                "a phrase is not a field of passcodeUnlock")
    }

    @Test func changeAndDisableRefuseAnUnlistedField() {
        let change: [String: Any] = ["type": "passcodeChange", "reqId": 7_000_000_000_003, "eoa": eoa,
                                     "oldPasscode": "123456", "newPasscode": "654321", "passcode": "123456"]
        #expect(PasscodeCommandWhitelist.refusal(for: change) == "bad_request")
        let disable: [String: Any] = ["type": "passcodeDisable", "reqId": 7_000_000_000_004, "eoa": eoa,
                                      "passcode": "123456", "newPasscode": "654321"]
        #expect(PasscodeCommandWhitelist.refusal(for: disable) == "bad_request")
    }

    @Test func statusCarriesNoCredential() {
        let ok: [String: Any] = ["type": "passcodeStatus", "reqId": 7_000_000_000_005, "eoa": eoa]
        #expect(PasscodeCommandWhitelist.refusal(for: ok) == nil)
        let bad: [String: Any] = ["type": "passcodeStatus", "reqId": 7_000_000_000_006, "eoa": eoa, "passcode": "123456"]
        #expect(PasscodeCommandWhitelist.refusal(for: bad) == "bad_request")
    }

    @Test func repairProvideCarriesItsRequestReqId() {
        let command: [String: Any] = ["type": "nativeRepairProvide", "reqId": 7_000_000_000_007, "eoa": eoa,
                                      "phrase": "synthetic phrase", "passcode": "123456", "requestReqId": 7_500_000_000_001]
        #expect(PasscodeCommandWhitelist.refusal(for: command) == nil)
    }

    @Test func aCommandOutsideTheTableCannotCarryACredentialField() {
        let other: [String: Any] = ["type": "pgpRestore", "reqId": 7_000_000_000_008, "eoa": eoa, "passcode": "123456"]
        #expect(PasscodeCommandWhitelist.refusal(for: other) == "bad_request")
        let phraseOnOther: [String: Any] = ["type": "walletStatus", "reqId": 7_000_000_000_009, "phrase": "synthetic phrase"]
        #expect(PasscodeCommandWhitelist.refusal(for: phraseOnOther) == "bad_request")
    }

    @Test func aCommandWithoutCredentialsPassesUnchanged() {
        let plain: [String: Any] = ["type": "walletStatus", "reqId": 7_000_000_000_010, "eoa": eoa]
        #expect(PasscodeCommandWhitelist.refusal(for: plain) == nil)
    }

    @Test func theRefusalNamesNoValue() {
        // The check returns only an error code: no value of any field is ever returned.
        let command: [String: Any] = ["type": "passcodeUnlock", "reqId": 7_000_000_000_011, "eoa": eoa, "phrase": "secret words"]
        let code = PasscodeCommandWhitelist.refusal(for: command) ?? ""
        #expect(!code.contains("secret"))
        #expect(code == "bad_request")
    }
}
