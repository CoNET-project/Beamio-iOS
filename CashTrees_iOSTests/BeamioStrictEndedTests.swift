import Foundation
import Testing
@testable import CashTrees_iOS
@testable import ConetChatSDK

// The strict {callId, sessionId} ended record only adds drops. Empty sessionId writes no strict record; the
// existing dual-key rule (and the push alias) is unchanged. Each test uses its own ids.
@Suite(.serialized)
struct BeamioStrictEndedTests {
	static let envelopeText = """
{"type":"voice_call_offer_v1","proto":3,"callId":"vt-env2-call-0001","sessionId":"vt-env2-session-0001","from":"0x5EAC5064D7BA0CcCf2Cb1B055A865e5b776CFd77","to":"0x000000000000000000000000000000000000dEaD","codec":"audio/pcm;rate=16000","callerPgp":"VEVTVC1GSVhUVVJFLVBHUC1BUk1PUi1OT1QtQS1SRUFMLUtFWQ==","callerRoute":"VEVTVC1GSVhUVVJFLVJPVVRFLU5PVC1BLVJFQUwtS0VZ","callerTag":"vt_caller","expiresAt":1795222709258,"createdAt":1795221809258,"timestamp":1795221809258,"callerSignature":"0xd44faafe5a615211e8e132e7391f51969e2a607bbecde628c56116698a61662c1b39c7731f1787939a0260f47f8cf851d9011675bc696dc13c63e84a0a7859261b"}
"""

	@Test func strictKeyIsJsonStringifyOfBothIdsOrNilWithoutSession() {
		#expect(BeamioNativeVoiceSignaling.strictEndedKeyString(callId: "sk-c1", sessionId: "sk-s1") == "[\"sk-c1\",\"sk-s1\"]")
		#expect(BeamioNativeVoiceSignaling.strictEndedKeyString(callId: "sk-c1", sessionId: "") == nil)
	}

	@Test func aReplayOfTheSameEndedHandleIsDropped() {
		BeamioNativeVoiceSignaling.markStrictEnded(callId: "sk-c2", sessionId: "sk-s2")
		#expect(BeamioNativeVoiceSignaling.wasStrictEnded(callId: "sk-c2", sessionId: "sk-s2"))
	}

	@Test func aNewSignalOfAnEndedCallIsDroppedByTheStrictKey() {
		BeamioNativeVoiceSignaling.markStrictEnded(callId: "sk-c3", sessionId: "sk-s3")
		let line = #"{"text":"{\"callId\":\"sk-c3\",\"sessionId\":\"sk-s3\"}","signMessage":"0x00","from":"0x1111111111111111111111111111111111111111"}"#
		let id = VoiceLineVerifier.innerIdentity(line)
		#expect(id?.callId == "sk-c3")
		#expect(BeamioNativeVoiceSignaling.wasStrictEnded(callId: id?.callId ?? "", sessionId: id?.sessionId ?? ""))
	}

	@Test func aDifferentSessionOfTheSameCallIsNotDroppedByTheStrictKey() {
		BeamioNativeVoiceSignaling.markStrictEnded(callId: "sk-c4", sessionId: "sk-s4")
		#expect(!BeamioNativeVoiceSignaling.wasStrictEnded(callId: "sk-c4", sessionId: "sk-s4-other"))
	}

	@Test func anEmptySessionWritesNoStrictRecordAndKeepsTheDualKeyRule() {
		BeamioNativeVoiceSignaling.markLocallyEnded(callId: "sk-c5", sessionId: "")
		#expect(!BeamioNativeVoiceSignaling.wasStrictEnded(callId: "sk-c5", sessionId: ""))
		#expect(BeamioNativeVoiceSignaling.wasLocallyEnded(callId: "sk-c5", sessionId: ""))
	}

	@Test func theEnvelopeSampleIdentityIsReadFromTheInnerSignal() {
		let line = String(decoding: try! JSONSerialization.data(withJSONObject: ["text": Self.envelopeText, "signMessage": "0x00", "from": "0x5EAC5064D7BA0CcCf2Cb1B055A865e5b776CFd77"]), as: UTF8.self)
		let id = VoiceLineVerifier.innerIdentity(line)
		#expect(id?.callId == "vt-env2-call-0001")
		#expect(id?.sessionId == "vt-env2-session-0001")
	}
}
