#if BEAMIO_TEST_HOOKS
import Foundation
import Testing
@testable import CashTrees_iOS

/// A late-arriving voice offer must not be applied to an ended call, and a late result after the wait is dropped.
/// Synthetic values only (placeholder addresses, a placeholder tag, no key material).
/// The live-call override is a shared static: the cases run one at a time (Swift Testing otherwise runs them in parallel).
@Suite(.serialized)
struct LateOfferGuardTests {
    private let callId = "push-call-0001"
    private let sessionId = "push-session-0001-synthetic"

    private func answerableOffer() -> BeamioVoiceOfferIdentity.Resolved {
        BeamioVoiceOfferIdentity.Resolved(
            callerEoa: "0x2222222222222222222222222222222222222222",
            beamioTag: "@synthetic",
            shortAddress: "0x2222…2222",
            callId: callId,
            sessionId: sessionId,
            to: "0x1111111111111111111111111111111111111111",
            proto: 3,
            callerPgpArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            callerRouteArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            signedExpiresAtMs: Date().timeIntervalSince1970 * 1000 + 600_000
        )
    }

    @Test func endedCallDropsALateOffer() {
        BeamioNativeVoiceSignaling.liveOverrideForTests = { _, _ in false }
        defer { BeamioNativeVoiceSignaling.liveOverrideForTests = nil }
        #expect(BeamioNativeVoiceSignaling.isCallStillLive(callId: callId, sessionId: sessionId) == false)
        #expect(BeamioNativeVoiceSignaling.shouldApplyLateOffer(answerableOffer(), callId: callId, sessionId: sessionId) == false)
    }

    @Test func liveCallAppliesALateAnswerableOffer() {
        BeamioNativeVoiceSignaling.liveOverrideForTests = { _, _ in true }
        defer { BeamioNativeVoiceSignaling.liveOverrideForTests = nil }
        #expect(BeamioNativeVoiceSignaling.shouldApplyLateOffer(answerableOffer(), callId: callId, sessionId: sessionId) == true)
    }

    @Test func aNonAnswerableOfferIsNotAppliedEvenIfLive() {
        BeamioNativeVoiceSignaling.liveOverrideForTests = { _, _ in true }
        defer { BeamioNativeVoiceSignaling.liveOverrideForTests = nil }
        var offer = answerableOffer()
        offer.proto = 2
        #expect(BeamioNativeVoiceSignaling.shouldApplyLateOffer(offer, callId: callId, sessionId: sessionId) == false)
    }

    @Test func aResultDeliveredAfterTheWaitIsDropped() {
        let box = BeamioNativeVoiceSignaling.OfferWaitBox()
        #expect(box.finish() == nil)
        box.deliver(answerableOffer())
        #expect(box.finish() == nil)
    }

    @Test func aResultDeliveredBeforeTheWaitEndsIsKept() {
        let box = BeamioNativeVoiceSignaling.OfferWaitBox()
        box.deliver(answerableOffer())
        #expect(box.finish()?.callId == callId)
    }

    // MARK: - The live rule, from the real stores (markers, CallKit presence, TTL). Each case resets what it sets.

    /// A test-unique push callId, so the process-wide stores never mix two cases.
    private func uniqueCallId(_ label: String) -> String {
        "push-live-\(label)-\(UUID().uuidString.prefix(8))"
    }

    @Test func anEndMarkerMakesTheCallEnded() {
        let id = uniqueCallId("marker")
        BeamioNativeVoiceSignaling.liveOverrideForTests = nil
        BeamioNativeVoiceSignaling.callKitPresentForTests = { _ in true }
        defer { BeamioNativeVoiceSignaling.callKitPresentForTests = nil }
        BeamioNativeVoiceSignaling.markLocallyEnded(callId: id, sessionId: "")
        #expect(BeamioNativeVoiceSignaling.isCallStillLive(callId: id, sessionId: "") == false)
    }

    @Test func aCallCallKitReportedAndNoLongerHoldsIsEnded() {
        let id = uniqueCallId("removed")
        BeamioNativeVoiceSignaling.liveOverrideForTests = nil
        BeamioNativeVoiceSignaling.callKitPresentForTests = { _ in false }
        defer { BeamioNativeVoiceSignaling.callKitPresentForTests = nil }
        BeamioNativeVoiceSignaling.noteIncomingRingStarted(callId: id)
        defer { BeamioNativeVoiceSignaling.setCallKitReportedAtForTests(callId: id, at: nil) }
        #expect(BeamioNativeVoiceSignaling.isCallStillLive(callId: id, sessionId: "") == false)
    }

    @Test func aCallCallKitNeverReportedIsLive() {
        let id = uniqueCallId("never")
        BeamioNativeVoiceSignaling.liveOverrideForTests = nil
        BeamioNativeVoiceSignaling.callKitPresentForTests = { _ in false }
        defer { BeamioNativeVoiceSignaling.callKitPresentForTests = nil }
        #expect(BeamioNativeVoiceSignaling.callKitReportedAt(callId: id) == nil)
        #expect(BeamioNativeVoiceSignaling.isCallStillLive(callId: id, sessionId: "") == true)
    }

    @Test func aCallOlderThanTheTTLIsEndedEvenWhenCallKitStillHoldsIt() {
        let id = uniqueCallId("ttl")
        BeamioNativeVoiceSignaling.liveOverrideForTests = nil
        BeamioNativeVoiceSignaling.callKitPresentForTests = { _ in true }
        defer { BeamioNativeVoiceSignaling.callKitPresentForTests = nil }
        let past = Date().addingTimeInterval(-(BeamioNativeVoiceSignaling.lateOfferCallTTLSeconds + 60))
        BeamioNativeVoiceSignaling.setCallKitReportedAtForTests(callId: id, at: past)
        defer { BeamioNativeVoiceSignaling.setCallKitReportedAtForTests(callId: id, at: nil) }
        #expect(BeamioNativeVoiceSignaling.isCallStillLive(callId: id, sessionId: "") == false)
    }

    @Test func aCallWithinTheTTLAndHeldByCallKitIsLive() {
        let id = uniqueCallId("fresh")
        BeamioNativeVoiceSignaling.liveOverrideForTests = nil
        BeamioNativeVoiceSignaling.callKitPresentForTests = { _ in true }
        defer { BeamioNativeVoiceSignaling.callKitPresentForTests = nil }
        BeamioNativeVoiceSignaling.setCallKitReportedAtForTests(callId: id, at: Date().addingTimeInterval(-5))
        defer { BeamioNativeVoiceSignaling.setCallKitReportedAtForTests(callId: id, at: nil) }
        #expect(BeamioNativeVoiceSignaling.isCallStillLive(callId: id, sessionId: "") == true)
    }

    /// Off the main thread, `isCallStillLive` (the real path, not the test hook) reads the CallKit map while other threads write it.
    /// The lock on the map makes this safe; without it the concurrent reads and writes race on the dictionary.
    /// Four writer threads run concurrently with the readers. The test exercises concurrent single accesses (each read and
    /// each write through the lock). It does not exercise a read-modify-write sequence as one unit.
    @Test func isCallStillLiveReadsTheCallKitMapSafelyFromBackgroundThreads() {
        let bootstrap = BeamioVoipIncomingBootstrap.shared
        let id = uniqueCallId("background")
        let uuids = (0..<8).map { _ in UUID() }
        BeamioNativeVoiceSignaling.liveOverrideForTests = nil
        BeamioNativeVoiceSignaling.callKitPresentForTests = nil
        BeamioNativeVoiceSignaling.setCallKitReportedAtForTests(callId: id, at: Date().addingTimeInterval(-5))
        defer {
            BeamioNativeVoiceSignaling.setCallKitReportedAtForTests(callId: id, at: nil)
            for uuid in uuids { bootstrap.callKit.setCallIdentityForTests(uuid: uuid, callId: nil) }
        }

        let group = DispatchGroup()
        let queue = DispatchQueue.global(qos: .userInitiated)
        let tally = NSLock()
        var answered = 0
        var answeredOffMain = 0
        for _ in 0..<4 {
            queue.async(group: group) {
                for _ in 0..<500 {
                    _ = BeamioNativeVoiceSignaling.isCallStillLive(callId: id, sessionId: "")
                    tally.lock()
                    answered += 1
                    if !Thread.isMainThread { answeredOffMain += 1 }
                    tally.unlock()
                }
            }
        }
        for writer in 0..<4 {
            queue.async(group: group) {
                for step in 0..<500 {
                    let slot = uuids[(writer * 2 + step) % uuids.count]
                    bootstrap.callKit.setCallIdentityForTests(uuid: slot, callId: step % 3 == 0 ? nil : id)
                }
            }
        }
        group.wait()

        #expect(answered == 2000, "every read returns")
        #expect(answeredOffMain == 2000, "every read ran off the main thread")

        for uuid in uuids { bootstrap.callKit.setCallIdentityForTests(uuid: uuid, callId: nil) }
        #expect(BeamioNativeVoiceSignaling.isCallStillLive(callId: id, sessionId: "") == false,
                "with CallKit no longer holding the call, the reported call is ended")
    }
}
#endif
