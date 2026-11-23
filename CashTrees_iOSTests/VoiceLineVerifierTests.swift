import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

// v68 §75: voice_ chat lines are verified before they drive a call action. Fixture: the PWA envelope sample v2
// (public values only). Positive, forged signature, changed text, line sender mismatch, missing inner from, bare signal.
// Nested in the serialized SdkStateSuite parent: this suite verifies through the SDK's shared OpenPGP host, and the suites
// there that switch accounts or restore end the session, which tears that host down (BeamioPasscodeSession, reason ends call resources).
// Run one after another, a verification never meets a teardown from a parallel suite (evidence: 12 rounds, all failures -8 torn down).
extension SdkStateSuite {
@Suite(.serialized)
struct VoiceLineVerifierTests {
	static let envelopeText = """
{"type":"voice_call_offer_v1","proto":3,"callId":"vt-env2-call-0001","sessionId":"vt-env2-session-0001","from":"0x5EAC5064D7BA0CcCf2Cb1B055A865e5b776CFd77","to":"0x000000000000000000000000000000000000dEaD","codec":"audio/pcm;rate=16000","callerPgp":"VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==","callerRoute":"VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ","callerTag":"vt_caller","expiresAt":1795222709258,"createdAt":1795221809258,"timestamp":1795221809258,"callerSignature":"0xd44faafe5a615211e8e132e7391f51969e2a607bbecde628c56116698a61662c1b39c7731f1787939a0260f47f8cf851d9011675bc696dc13c63e84a0a7859261b"}
"""
	static let signMessage = "0x2c05f7978d5ff9ea16d97c275dde953a5ca7e095c609e68c80941d96b3d9e0d61320d7def566ca415cbbed947415c5f14cc951c5df00ed59b4edf75eb2819d831b"
	static let envelopeFrom = "0x5EAC5064D7BA0CcCf2Cb1B055A865e5b776CFd77"

	static func line(text: String = envelopeText, signature: String = signMessage, from: String = envelopeFrom) -> String {
		let obj: [String: Any] = ["text": text, "signMessage": signature, "from": from]
		return String(decoding: try! JSONSerialization.data(withJSONObject: obj), as: UTF8.self)
	}

	static func verify(_ line: String, from: String, nowMs: Double = 1_795_221_869_258) async -> Bool {
		await withCheckedContinuation { cont in
			VoiceLineVerifier.verify(line: line, lineFrom: from, nowMs: nowMs) { cont.resume(returning: $0) }
		}
	}

	@Test func positiveSampleVerifies() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		let ok = await Self.verify(Self.line(), from: Self.envelopeFrom)
		if !ok { await TestSupportSdkState.recordHostFailure("positiveSampleVerifies") }
		#expect(ok)
	}

	@Test func forgedSignatureIsDropped() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		#expect(!(await Self.verify(Self.line(signature: "0x" + String(repeating: "11", count: 65)), from: Self.envelopeFrom)))
	}

	@Test func changedTextWithAValidSignatureOfAnotherTextIsDropped() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		#expect(!(await Self.verify(Self.line(text: Self.envelopeText + " "), from: Self.envelopeFrom)))
	}

	@Test func lineSenderMismatchIsDropped() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		#expect(!(await Self.verify(Self.line(), from: "0x1111111111111111111111111111111111111111")))
	}

	@Test func missingInnerFromIsDropped() {
		let withoutFrom = #"{"type":"voice_call_ringing_v1","callId":"vt-env2-call-0001"}"#
		#expect(VoiceLineVerifier.innerFrom(withoutFrom) == nil)
	}

	@Test func aBareSignalIsNotAnEnvelope() {
		let bare = #"{"type":"voice_end_v1","callId":"vt-env2-call-0001","from":"0x5EAC5064D7BA0CcCf2Cb1B055A865e5b776CFd77"}"#
		#expect(VoiceLineVerifier.envelope(bare) == nil)
	}

	@Test func verificationLatencyIsMeasured() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		var times: [Double] = []
		for _ in 0..<15 {
			let start = Date()
			_ = await Self.verify(Self.line(), from: Self.envelopeFrom)
			times.append(Date().timeIntervalSince(start) * 1000)
		}
		let sorted = times.sorted()
		let report = "VOICE-VERIFY-LATENCY-MS median=\(sorted[sorted.count / 2]) max=\(sorted.last ?? 0) n=\(sorted.count)\n"
		print(report)
		#expect(sorted.count == 15)
	}

	@Test func staleButValidlySignedSignalIsDropped() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		// Replay guard: the same valid signature after the sample's expiresAt (1795222709258) must not drive state.
		#expect(!(await Self.verify(Self.line(), from: Self.envelopeFrom, nowMs: 1_795_222_709_259)))
	}

	@Test func aSignalWithinItsLifetimeStillVerifies() async {
		guard await TestSupportSdkState.requireVerificationHost() else { return }
		let ok = await Self.verify(Self.line(), from: Self.envelopeFrom, nowMs: 1_795_221_900_000)
		if !ok { await TestSupportSdkState.recordHostFailure("aSignalWithinItsLifetimeStillVerifies") }
		#expect(ok)
	}
}
}
