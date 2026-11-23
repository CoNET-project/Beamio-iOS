import Foundation
import Testing
@testable import CashTrees_iOS

extension SdkStateSuite {
    @Suite(.serialized)
    struct NativeBridgeTrustTests {
        private func trusted(
            isMainFrame: Bool = true,
            scheme: String = "cashtrees-local",
            host: String = "localhost",
            port: Int = 0,
            version: String = NativeBridgeTrust.expectedPwaVersion,
            zipSHA: String = NativeBridgeTrust.expectedEmbeddedZipSHA256,
            treeSHA: String = NativeBridgeTrust.expectedActiveTreeSHA256
        ) -> Bool {
            NativeBridgeTrust.isTrusted(
                isMainFrame: isMainFrame,
                scheme: scheme,
                host: host,
                port: port,
                activeVersion: version,
                embeddedZipSHA256: zipSHA,
                activeTreeSHA256: treeSHA
            )
        }

        @Test func exactEmbeddedMainFrameIsTrusted() {
            #expect(trusted())
        }

        @Test func remoteOriginSubframeAndLookalikeAreRejected() {
            #expect(!trusted(scheme: "https", host: "beamio.app"))
            #expect(!trusted(isMainFrame: false))
            #expect(!trusted(host: "localhost.evil.example"))
            #expect(!trusted(port: 443))
        }

        @Test func versionZipAndActiveTreeMustAllMatch() {
            #expect(!trusted(version: "0.53.38"))
            #expect(!trusted(zipSHA: String(repeating: "0", count: 64)))
            #expect(!trusted(treeSHA: String(repeating: "0", count: 64)))
        }

        @Test func arbitraryPagePgpDecryptIsNotAllowed() {
            #expect(!NativeBridgeTrust.allowsPageCommand("pgpDecryptInbound"))
            #expect(NativeBridgeTrust.allowsPageCommand("hello"))
            #expect(NativeBridgeTrust.allowsPageCommand("init"))
        }

        @Test func staleOrMissingDocumentGenerationFailsClosedAfterPromotion() {
            #expect(NativeBridgeTrust.documentGenerationMatches(
                capturedAtNavigation: NativeBridgeTrust.expectedActiveTreeSHA256,
                currentActive: NativeBridgeTrust.expectedActiveTreeSHA256
            ))
            #expect(!NativeBridgeTrust.documentGenerationMatches(
                capturedAtNavigation: NativeBridgeTrust.expectedActiveTreeSHA256,
                currentActive: String(repeating: "a", count: 64)
            ))
            #expect(!NativeBridgeTrust.documentGenerationMatches(
                capturedAtNavigation: nil,
                currentActive: NativeBridgeTrust.expectedActiveTreeSHA256
            ))
        }

        @Test func committedDocumentURLMustMatchFrameRequestURL() {
            let committed = URL(string: "cashtrees-local://localhost/index.html")
            let sameDocument = URL(string: "cashtrees-local://localhost/index.html")
            let differentDocument = URL(string: "cashtrees-local://localhost/evil.html")
            #expect(committed?.absoluteString == sameDocument?.absoluteString)
            #expect(committed?.absoluteString != differentDocument?.absoluteString)
        }
    }
}
