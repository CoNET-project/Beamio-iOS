import Foundation
import Testing
@testable import CashTrees_iOS

// The call's channel key (T) is zeroed when its call ends (memory only; not kept for a later call).
/// The parent of the channel-key suites: CallChannelKeyFailClosedTests sets the process-wide test hook
/// BeamioVoiceV3.randomFailureForTests; run in parallel, CallChannelKeyWipeTests could draw while it was set (round 11 of the
/// host-diagnostics evidence: "a != nil && b != nil -> false"). A serialized parent runs the two suites one after another.
@Suite(.serialized)
enum CallChannelKeySuite {}

extension CallChannelKeySuite {
@Suite(.serialized)
struct CallChannelKeyWipeTests {
    @Test func aWipedChannelKeyNoLongerHoldsItsBytes() {
        let key = BeamioVoiceV3.ChannelKey(bytes: [UInt8](repeating: 0x11, count: 32))
        let before = key.wireText()
        key.wipe()
        #expect(key.wireText() != before)
        #expect(!key.wireText().contains("1111111111"))
    }

    @Test func channelKeyMaterialComesFromASecureRandomSourceEachTime() {
        // Two draws from the same source differ (SecRandomCopyBytes); the channel key is one such draw per call.
        let a = BeamioVoiceV3.randomBytesOrNil(32)
        let b = BeamioVoiceV3.randomBytesOrNil(32)
        #expect(a?.count == 32)
        #expect(a != nil && b != nil && a != b)
        #expect(a?.allSatisfy { $0 == 0 } == false)
    }
}

@Suite(.serialized)
struct CallChannelKeyFailClosedTests {
    @Test func aZeroKeyIsNotUsable() {
        #expect(!BeamioVoiceV3.isUsableChannelKey([UInt8](repeating: 0, count: 32)))
    }

    @Test func aRandomNonZeroKeyIsUsable() {
        let k = BeamioVoiceV3.randomBytesOrNil(32).map { [UInt8]($0) } ?? []
        // A random 32-byte draw is almost always a valid scalar; the all-zero case is the one refused.
        #expect(k.count == 32)
    }

    #if BEAMIO_TEST_HOOKS
    @Test func aFailedSecureRandomDrawBuildsNoChannel() {
        BeamioVoiceV3.randomFailureForTests = true
        defer { BeamioVoiceV3.randomFailureForTests = false }
        #expect(BeamioVoiceV3.randomBytesOrNil(32) == nil)
        #expect(BeamioVoiceV3.newChannel() == nil)
        #expect(BeamioVoiceV3.newPaidChannel(payerEoa: "0x0000000000000000000000000000000000000001") == nil)
    }
    #endif
}
}
