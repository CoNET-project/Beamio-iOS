import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

/// The shell's mapping of the SDK's pgpDecrypt failures (an unreadable PGP record is storageUnreadable, not
/// no_pgp_key). Synthetic values only; nothing here reads a key or changes production code.
struct DecryptFailureMappingTests {
    @Test func unreadableRecordMapsToDecryptUnknownNotKeyMissing() {
        let mapped = BeamioDecryptFailureState.of(.storageUnreadable)
        #expect(mapped.state == .decryptUnknown)
        #expect(mapped.reason == .decryptUnknown)
        #expect(mapped.state != .keyMissing)
    }

    @Test func absentRecordStillMapsToKeyMissing() {
        let mapped = BeamioDecryptFailureState.of(.rejected("no_pgp_key"))
        #expect(mapped.state == .keyMissing)
        #expect(mapped.reason == .keyMissing)
    }

    @Test func unreadableAndAbsentAreDistinctStates() {
        let unreadable = BeamioDecryptFailureState.of(.storageUnreadable).state
        let absent = BeamioDecryptFailureState.of(.rejected("no_pgp_key")).state
        #expect(unreadable != absent)
    }
}
