import Foundation
import Testing
@testable import ConetChatSDK
@testable import CashTrees_iOS

// Native voice-offer decryption (BeamioNativeWallet.pgpDecrypt, the path the voice offer uses). Synthetic keys and an
// openpgp.js-encrypted offer, generated for this test (vector file SHA256 f8d3c76c704a0fb3ddcfcede240d26b00266537a311879f7ca4c6e0e28f2b5d5).
// The X-19 framework is linked in this build; positive and negative cases run natively, with no WebView.
private let offerPlaintext = "{\"type\":\"voice_offer\",\"callId\":\"synthetic-call-0001\",\"sessionId\":\"synthetic-session-0001\",\"sid\":\"synthetic-sid-0001\",\"createdAt\":1700000000000,\"note\":\"synthetic offer\"}"
private let offerCipher = "-----BEGIN PGP MESSAGE-----\n\nwV4DBS23zAwhUWYSAQdAAG1QEXu/3tNNnjXAtJCWElo1cACMSxPcC36keHTt\nMSgwhDvfUaRym25AJFhtDrBoC53aU+dsSiPxU5BTr5xpxt646lFZrI/oAqk1\nYXATOUkU0sAZAdCSe0QN3TjcpgG+wgZC8NwZ/zR+gZp9gVGjBCCC9oxyJefU\nkUV7gEYdoRtXVpzSRXDGtQmYTAwMOd+zW6QqsfajiuHTo8U8XiM9mPiNFKaX\nMPog9OBNhj7ixxMRfXa/C/v9+pDMH8QON1YCS2xJXd7jwujyxy0UDfmo6Fvm\nNjerRPVmPOKy1Jc+rt34+DANVMjjvbsIh2+QcR6JPKb+OfdDx8hLKssBiTjN\npcDUxvrO405g6T/BmwdXIHJi+rtnSs1H3njZP+bmgPii6L3XGpwc+ny2/d8u\nwg==\n=pe/Z\n-----END PGP MESSAGE-----\n"
private let recipientPrivate = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxVgEav0NVRYJKwYBBAHaRw8BAQdA0lsUZ44DvNd4soaIn8I/Z+ptuBHPyXbf\nk0a9aZO/+wsAAP4joZulMiGdhKpPT1y+duc7FeTPzCc2f/OZBIExMR0vTA7r\nzS9zeW50aGV0aWMtcmVjaXBpZW50IDxzeW50aGV0aWNAZXhhbXBsZS5pbnZh\nbGlkPsLAEwQTFgoAhQWCav0NVQMLCQcJEGkEEaNz9KB2RRQAAAAAABwAIHNh\nbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmfrqVrfd80pM5gHdUA0oRYlCcKG\nvILA58T2mOWElL/aEgUVCggODAQWAAIBAhkBApsDAh4BFiEE6lU5Yt674PV9\nVFasaQQRo3P0oHYAAOA6AQD06neO6dpjVnwNH8O/apjaFUbQGOITTq5xn6aR\nNthgzgD/Sd/rOygUPkYLKMTw9cG/DnLGSbXfVkRlnftccnEYBQjHXQRq/Q1V\nEgorBgEEAZdVAQUBAQdAuJT4blPQHm6Cx+xQ2F64O4QcsFO51P3nWR0Z6N4n\nfhADAQgHAAD/ct52P5/Qxk2PZ/wBcgfgO+W7W0+inK4CEwZeKeUDa8gQAMK+\nBBgWCgBwBYJq/Q1VCRBpBBGjc/SgdkUUAAAAAAAcACBzYWx0QG5vdGF0aW9u\ncy5vcGVucGdwanMub3JnpXqsO90AxR1cSnvWeowW/9gisErpntUCdTttPXJA\n+j8CmwwWIQTqVTli3rvg9X1UVqxpBBGjc/SgdgAAyp8A/RmIbZ6iPQmLXB6P\nEnKDpz4U7dNA4Nfh0qbbqRcGRZOqAQCiZY/ZGQsy2X7YsHVyfU0uBI9DeO1c\n7vNo90X7wDIwAA==\n=3iDJ\n-----END PGP PRIVATE KEY BLOCK-----\n"
private let recipientPublic = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEav0NVRYJKwYBBAHaRw8BAQdA0lsUZ44DvNd4soaIn8I/Z+ptuBHPyXbf\nk0a9aZO/+wvNL3N5bnRoZXRpYy1yZWNpcGllbnQgPHN5bnRoZXRpY0BleGFt\ncGxlLmludmFsaWQ+wsATBBMWCgCFBYJq/Q1VAwsJBwkQaQQRo3P0oHZFFAAA\nAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ+upWt93zSkzmAd1\nQDShFiUJwoa8gsDnxPaY5YSUv9oSBRUKCA4MBBYAAgECGQECmwMCHgEWIQTq\nVTli3rvg9X1UVqxpBBGjc/SgdgAA4DoBAPTqd47p2mNWfA0fw79qmNoVRtAY\n4hNOrnGfppE22GDOAP9J3+s7KBQ+RgsoxPD1wb8OcsZJtd9WRGWd+1xycRgF\nCM44BGr9DVUSCisGAQQBl1UBBQEBB0C4lPhuU9AeboLH7FDYXrg7hBywU7nU\n/edZHRno3id+EAMBCAfCvgQYFgoAcAWCav0NVQkQaQQRo3P0oHZFFAAAAAAA\nHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ6V6rDvdAMUdXEp71nqM\nFv/YIrBK6Z7VAnU7bT1yQPo/ApsMFiEE6lU5Yt674PV9VFasaQQRo3P0oHYA\nAMqfAP0ZiG2eoj0Ji1wejxJyg6c+FO3TQODX4dKm26kXBkWTqgEAomWP2RkL\nMtl+2LB1cn1NLgSPQ3jtXO7zaPdF+8AyMAA=\n=HwqB\n-----END PGP PUBLIC KEY BLOCK-----\n"
private let otherPrivate = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nxVgEav0NVRYJKwYBBAHaRw8BAQdA9AnBn9mS2AsfPU6aQJk954czXNz6zrhN\n/0tZTmMPWBYAAQD6Sd26Z2TT5ojLe/366HUL5ZqbzqhBTglDDZH0mx08hBIB\nzStzeW50aGV0aWMtb3RoZXIgPHN5bnRoZXRpY0BleGFtcGxlLmludmFsaWQ+\nwsATBBMWCgCFBYJq/Q1VAwsJBwkQqboOCda1FedFFAAAAAAAHAAgc2FsdEBu\nb3RhdGlvbnMub3BlbnBncGpzLm9yZ9ZF777t4JFO6HyUZJamWZ2i0vUmHvIf\ncLmy9xpZGkXeBRUKCA4MBBYAAgECGQECmwMCHgEWIQRFd/Rkwb/99Ep2vaWp\nug4J1rUV5wAAVsABAMygbFaYsPxkhnTb7+Aq4SRLUBX9g9Sq6PiytIobhwv4\nAP9ltIACUwX4gzl62VaM1rBBu87c8h7WwaEq/1t9xMuQC8ddBGr9DVUSCisG\nAQQBl1UBBQEBB0D9GRrujsmgqRfbBEHpqrZRCNzke4qwpfzvXrinNTf5YwMB\nCAcAAP91LGNcvvu+ZKzpos+lJRyr2n4THB8rJ0T35rPU8gj+GBGBwr4EGBYK\nAHAFgmr9DVUJEKm6DgnWtRXnRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9w\nZW5wZ3Bqcy5vcmeOZkv5UsP7u9OX0Knig9SnShTuMZQikvUXx4oo94vyZgKb\nDBYhBEV39GTBv/30Sna9pam6DgnWtRXnAAAKsAD/Rl4qYeu1s92YiC1Ryb6v\nFDFEziF5UnuJgxQBN0USwI0BAM3ZdeMQjnoFQcB8XZ06OTEc0bweUWlUUF1A\nO3dE1dkN\n=k6JY\n-----END PGP PRIVATE KEY BLOCK-----\n"
private let offerAccount = "0x1111111111111111111111111111111111111111"

private let tamperedSessionKeyCipher = "-----BEGIN PGP MESSAGE-----\n\nwV4DBS23zAwhUWYSAQdAAG1QEXu/3tNNnjXAtJCWE1o1cACMSxPcC36keHTtMSgw\nhDvfUaRym25AJFhtDrBoC53aU+dsSiPxU5BTr5xpxt646lFZrI/oAqk1YXATOUkU\n0sAZAdCSe0QN3TjcpgG+wgZC8NwZ/zR+gZp9gVGjBCCC9oxyJefUkUV7gEYdoRtX\nVpzSRXDGtQmYTAwMOd+zW6QqsfajiuHTo8U8XiM9mPiNFKaXMPog9OBNhj7ixxMR\nfXa/C/v9+pDMH8QON1YCS2xJXd7jwujyxy0UDfmo6FvmNjerRPVmPOKy1Jc+rt34\n+DANVMjjvbsIh2+QcR6JPKb+OfdDx8hLKssBiTjNpcDUxvrO405g6T/BmwdXIHJi\n+rtnSs1H3njZP+bmgPii6L3XGpwc+ny2/d8uwg==\n=T9+i\n-----END PGP MESSAGE-----"
private let otherAccount = "0x2222222222222222222222222222222222222222"

extension SdkStateSuite {
    @Suite(.serialized)
    struct NativeVoiceOfferDecryptTests {
        init() {
            BeamioNativeAccountPointer.clear()
        }

        /// Stores one PGP secret for the synthetic account in the memory records, for one case; restores the records after.
        private func withStoredKey(_ privateArmor: String, _ body: () -> Void) {
            let saved = BeamioChatPgpKeychain.memory
            BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
            defer { BeamioChatPgpKeychain.memory = saved }
            let secrets = BeamioChatPgpKeychain.Secrets(
                privateKeyArmor: privateArmor, publicKeyArmor: recipientPublic, pgpKeyId: "", routePublicKeyArmor: "",
                entryDomains: [], siNodes: [], mailboxIp: "", eoa: offerAccount)
            #expect(BeamioChatPgpKeychain.save(secrets), "the synthetic PGP secret is stored for the account")
            body()
        }

        @Test func offerEncryptedToTheStoredKeyDecryptsToItsContent() {
            withStoredKey(recipientPrivate) {
                #expect(BeamioNativeWallet.pgpDecrypt(eoa: offerAccount, message: Data(offerCipher.utf8))
                        == .success(Data(offerPlaintext.utf8)), "the native decrypt returns the offer content unchanged")
            }
        }

        @Test func offerDoesNotDecryptWithAnotherKeyAndFailsCleanly() {
            withStoredKey(otherPrivate) {
                let started = Date()
                let result = BeamioNativeWallet.pgpDecrypt(eoa: offerAccount, message: Data(offerCipher.utf8))
                let elapsed = Date().timeIntervalSince(started)
                if case .success = result { Issue.record("a wrong private key must not decrypt the offer") }
                #expect(!String(describing: result).contains("synthetic-call-0001"), "the failure carries no plaintext")
                #expect(elapsed < 2, "the failure is immediate: no WebView round trip")
            }
        }

        @Test func tamperedOfferFailsCleanly() {
            withStoredKey(recipientPrivate) {
                // Change one character inside the armored body (not the header lines).
                var chars = Array(offerCipher)
                let mid = chars.count / 2
                chars[mid] = chars[mid] == "A" ? "B" : "A"
                let tampered = String(chars)
                let result = BeamioNativeWallet.pgpDecrypt(eoa: offerAccount, message: Data(tampered.utf8))
                if case .success = result { Issue.record("a tampered offer must not decrypt") }
                #expect(!String(describing: result).contains("synthetic-call-0001"), "the failure carries no plaintext")
            }
        }

        @Test func malformedArmorFailsCleanly() {
            withStoredKey(recipientPrivate) {
                let broken = "-----BEGIN PGP MESSAGE-----\n\nnot-a-real-message\n-----END PGP MESSAGE-----"
                let started = Date()
                let result = BeamioNativeWallet.pgpDecrypt(eoa: offerAccount, message: Data(broken.utf8))
                let elapsed = Date().timeIntervalSince(started)
                if case .success = result { Issue.record("malformed armor must not decrypt") }
                #expect(elapsed < 2, "the malformed armor is refused at once")
            }
        }

        @Test func nonArmoredInputIsRefusedWithAShapeError() {
            withStoredKey(recipientPrivate) {
                let result = BeamioNativeWallet.pgpDecrypt(eoa: offerAccount, message: Data("plain text, not armor".utf8))
                #expect(result == .failure(.rejected("pgp_message_shape")), "non-armored input is refused by shape")
            }
        }

        @Test func offerForAnotherAccountIsRefusedWithoutDecrypting() {
            withStoredKey(recipientPrivate) {
                let result = BeamioNativeWallet.pgpDecrypt(eoa: otherAccount, message: Data(offerCipher.utf8))
                if case .success = result { Issue.record("an offer for another account must not decrypt") }
                #expect(result == .failure(.rejected("no_pgp_key")), "the account mismatch is refused, nothing is decrypted")
                #expect(!String(describing: result).contains("synthetic-call-0001"), "the failure carries no plaintext")
            }
        }

        @Test func offerWithNoKeyRecordIsRefused() {
            let saved = BeamioChatPgpKeychain.memory
            BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
            defer { BeamioChatPgpKeychain.memory = saved }
            let result = BeamioNativeWallet.pgpDecrypt(eoa: offerAccount, message: Data(offerCipher.utf8))
            if case .success = result { Issue.record("with no key record the offer must not decrypt") }
            #expect(result == .failure(.rejected("no_pgp_key")), "no key record on this device: refused")
        }

        @Test func tamperedSessionKeyEncapsulationFailsCleanly() {
            withStoredKey(recipientPrivate) {
                // Only the encrypted session key packet is changed (one byte, CRC recomputed); the body is untouched.
                let started = Date()
                let result = BeamioNativeWallet.pgpDecrypt(eoa: offerAccount, message: Data(tamperedSessionKeyCipher.utf8))
                let elapsed = Date().timeIntervalSince(started)
                if case .success = result { Issue.record("a tampered session key packet must not decrypt the offer") }
                #expect(!String(describing: result).contains("synthetic-call-0001"), "the failure carries no plaintext")
                #expect(elapsed < 2, "the failure is immediate: no WebView round trip")
            }
        }
    }
}
