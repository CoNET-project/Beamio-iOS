import Foundation
import Testing
@testable import CashTrees_iOS

// v49 §55: the inbound chat line must be the envelope (text, signMessage, from). A bare offer is refused.
@Suite(.serialized)
struct BeamioInboundEnvelopeTests {
    static let callerFrom = "0x660fc041ffe39750ef53149debb5cf2df32c5b0f"
    static let bareOffer = #"{"type":"voice_call_offer_v1","proto":3,"callId":"vt-call-0001","sessionId":"vt-session-0001","from":"0x660fc041ffe39750ef53149debb5cf2df32c5b0f"}"#

    static func envelope(from: String, text: String = "{}") -> String {
        let obj: [String: Any] = ["text": text, "signMessage": "0x00", "from": from]
        return String(decoding: try! JSONSerialization.data(withJSONObject: obj), as: UTF8.self)
    }

    @Test func parseEnvelopeAcceptsTheEnvelopeFields() {
        let env = BeamioVoiceOfferIdentity.parseEnvelope(Self.envelope(from: Self.callerFrom, text: "inner"))
        #expect(env?.text == "inner")
        #expect(env?.from == Self.callerFrom)
    }

    @Test func parseEnvelopeRefusesABareOffer() {
        #expect(BeamioVoiceOfferIdentity.parseEnvelope(Self.bareOffer) == nil)
    }

    @Test func bareOfferIsRefusedByTheInboundLinePathWithoutAnyNetwork() async {
        let result: BeamioVoiceOfferIdentity.Resolved? = await withCheckedContinuation { cont in
            BeamioVoiceOfferIdentity.resolveFromInboundChatLine(line: Self.bareOffer, from: Self.callerFrom) { cont.resume(returning: $0) }
        }
        #expect(result == nil)
    }

    @Test func envelopeFromThatDoesNotMatchTheLineSenderIsRefusedWithoutAnyNetwork() async {
        let result: BeamioVoiceOfferIdentity.Resolved? = await withCheckedContinuation { cont in
            BeamioVoiceOfferIdentity.resolveFromInboundChatLine(
                line: Self.envelope(from: "0x1111111111111111111111111111111111111111"),
                from: Self.callerFrom
            ) { cont.resume(returning: $0) }
        }
        #expect(result == nil)
    }
}
