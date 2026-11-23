import Foundation
import Testing
@testable import CashTrees_iOS

// Two ringing calls, one dismissed: only the snapshot of the dismissed call (callId and sessionId) may be cleared.
@Suite(.serialized)
struct BeamioStickySnapshotTests {
    @Test func dismissingCallADoesNotMatchCallBsSnapshot() {
        #expect(!BeamioCallKitManager.stickySnapshotMatches(
            snapshotCallId: "call-b-0001", snapshotSessionId: "sess-b",
            dismissedCallId: "call-a-0001", dismissedSessionId: "sess-a"
        ))
    }

    @Test func dismissingCallBMatchesItsOwnSnapshot() {
        #expect(BeamioCallKitManager.stickySnapshotMatches(
            snapshotCallId: "call-b-0001", snapshotSessionId: "sess-b",
            dismissedCallId: "call-b-0001", dismissedSessionId: "sess-b"
        ))
    }

    @Test func sameCallIdWithAnotherSessionIdDoesNotMatch() {
        #expect(!BeamioCallKitManager.stickySnapshotMatches(
            snapshotCallId: "call-b-0001", snapshotSessionId: "sess-b",
            dismissedCallId: "call-b-0001", dismissedSessionId: "sess-other"
        ))
    }
}
