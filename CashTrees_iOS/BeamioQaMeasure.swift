#if BEAMIO_QA_MEASURE
import Foundation

/// QA-only measurement switch for the incoming-answer timing run (A1: answer
/// action not fulfilled). Compiled only when BEAMIO_QA_MEASURE is defined,
/// which the QA build sets and the release build never does. Verified by nm.
enum BeamioQaMeasure {
    /// True only when the QA launch environment sets BEAMIO_QA_DEFER_FULFILL=1.
    static var deferFulfill: Bool {
        ProcessInfo.processInfo.environment["BEAMIO_QA_DEFER_FULFILL"] == "1"
    }
}
#endif
