import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

/// reqId and seq boundaries (synthetic values only). PWA ranges: a pre-read reqId is 3e12 + a millisecond seq (13 digits, about 4.7e12);
/// a sync reqId is 900000000 + seq. Every value stays exact in a JSON number up to 2^53 − 1. Nothing here changes production code.
struct PwaReqIdBoundaryTests {
    /// A 13-digit pre-read style reqId (synthetic).
    private let thirteenDigitReqId = 4_700_000_000_123

    @Test func shellParsesThirteenDigitReqIdExactly() {
        let parsed = PwaWalletSyncBridge.strictInteger(NSNumber(value: thirteenDigitReqId), minimum: 1)
        #expect(parsed == thirteenDigitReqId)
    }

    @Test func sdkEchoesThirteenDigitReqIdUnchanged() {
        let echoed = BeamioChatRouteRegister.reqIdEcho(NSNumber(value: thirteenDigitReqId)) as? Int
        #expect(echoed == thirteenDigitReqId)
    }

    @Test func ackCarriesThirteenDigitReqIdAsAnInteger() {
        let ack = BeamioChatRouteRegister.ackEnvelope(reqId: thirteenDigitReqId, result: nil, error: "synthetic")
        #expect(ack["reqId"] as? Int == thirteenDigitReqId)
    }

    @Test func shellAcceptsTheLargestSafeIntegerAndRefusesTheNext() {
        let largest = 9_007_199_254_740_991
        #expect(PwaWalletSyncBridge.strictInteger(NSNumber(value: largest), minimum: 0) == largest)
        #expect(PwaWalletSyncBridge.strictInteger(NSNumber(value: largest + 1), minimum: 0) == nil)
    }

    @Test func sdkSeqAcceptsTheLargestSafeIntegerAndRefusesTheNext() {
        let largest = 9_007_199_254_740_991
        #expect(BeamioPwaSeq.parse(NSNumber(value: largest)) == Int64(largest))
        #expect(BeamioPwaSeq.parse(NSNumber(value: largest + 1)) == nil)
    }
}
