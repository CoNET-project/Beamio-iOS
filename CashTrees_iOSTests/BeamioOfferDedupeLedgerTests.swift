import Foundation
import Testing
@testable import CashTrees_iOS

// Chat interface spec: dedupe key, per-R quota 50, global quota 1000, expired purge first, fail closed.
@Suite(.serialized)
struct BeamioOfferDedupeLedgerTests {
    private let now: Double = 1_800_000_000_000
    private let future: Double = 1_800_000_900_000
    private let past: Double = 1_799_999_000_000

    private func caller(_ n: Int) -> String {
        "0x" + String(format: "%040x", n)
    }

    @Test func keyIsJsonStringifyOfTheTwoIds() {
        #expect(BeamioOfferDedupeLedger.key(callId: "c-1", sessionId: "s_2") == "[\"c-1\",\"s_2\"]")
    }

    @Test func replayOfARecordedOfferIsAdmittedWithoutANewRecord() {
        var ledger = BeamioOfferDedupeLedger()
        #expect(ledger.admit(callId: "c", sessionId: "s", callerEoa: caller(1), expiresAtMs: future, nowMs: now) == .admitted)
        #expect(ledger.admit(callId: "c", sessionId: "s", callerEoa: caller(1), expiresAtMs: future, nowMs: now) == .admitted)
        #expect(ledger.entries.count == 1)
    }

    @Test func perCallerQuotaRefusesTheFiftyFirstOfferOfThatCallerOnly() {
        var ledger = BeamioOfferDedupeLedger()
        for i in 0..<BeamioOfferDedupeLedger.perCallerLimit {
            #expect(ledger.admit(callId: "c\(i)", sessionId: "s", callerEoa: caller(1), expiresAtMs: future, nowMs: now) == .admitted)
        }
        #expect(ledger.admit(callId: "over", sessionId: "s", callerEoa: caller(1), expiresAtMs: future, nowMs: now) == .rejectedCallerQuota)
        // Another caller is not affected.
        #expect(ledger.admit(callId: "other", sessionId: "s", callerEoa: caller(2), expiresAtMs: future, nowMs: now) == .admitted)
    }

    @Test func expiredRecordsArePurgedBeforeTheQuotaIsChecked() {
        var ledger = BeamioOfferDedupeLedger()
        for i in 0..<BeamioOfferDedupeLedger.perCallerLimit {
            _ = ledger.admit(callId: "old\(i)", sessionId: "s", callerEoa: caller(1), expiresAtMs: past, nowMs: past - 1)
        }
        #expect(ledger.admit(callId: "fresh", sessionId: "s", callerEoa: caller(1), expiresAtMs: future, nowMs: now) == .admitted)
        #expect(ledger.entries.count == 1)
    }

    @Test func unexpiredRecordsAreNeverEvicted() {
        var ledger = BeamioOfferDedupeLedger()
        for i in 0..<BeamioOfferDedupeLedger.perCallerLimit {
            _ = ledger.admit(callId: "live\(i)", sessionId: "s", callerEoa: caller(1), expiresAtMs: future, nowMs: now)
        }
        #expect(ledger.admit(callId: "x", sessionId: "s", callerEoa: caller(1), expiresAtMs: future, nowMs: now) == .rejectedCallerQuota)
        #expect(ledger.entries.count == BeamioOfferDedupeLedger.perCallerLimit)
        #expect(ledger.entries["[\"live0\",\"s\"]"] != nil)
    }

    @Test func globalQuotaRefusesWhenFull() {
        var ledger = BeamioOfferDedupeLedger()
        for i in 0..<BeamioOfferDedupeLedger.globalLimit {
            _ = ledger.admit(callId: "g\(i)", sessionId: "s", callerEoa: caller(1000 + i / 50), expiresAtMs: future, nowMs: now)
        }
        #expect(ledger.entries.count == BeamioOfferDedupeLedger.globalLimit)
        #expect(ledger.admit(callId: "extra", sessionId: "s", callerEoa: caller(99_999), expiresAtMs: future, nowMs: now) == .rejectedGlobalQuota)
    }
}
