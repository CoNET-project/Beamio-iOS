import Foundation
import Testing
@testable import CashTrees_iOS

/// The document check of `NativeBridgeTrust.bundleTrusted` ignores only the fragment (the page's HashRouter route). Every other
/// part of the URL, and every other axis (main frame, origin, generation, embedded zip, active bundle), still refuses on its own.
@Suite struct NativeBridgeTrustFragmentTests {
	private let committed = "cashtrees-local://localhost/index.html"

	private func gate(
		frame: String?,
		committed: String? = "cashtrees-local://localhost/index.html",
		isMainFrame: Bool = true,
		scheme: String = CashTreesPWAScheme.scheme,
		host: String = CashTreesPWAScheme.host,
		port: Int = 0,
		generation: Bool = true,
		zip: Bool = true,
		bundle: Bool = true
	) -> Bool {
		NativeBridgeTrust.bundleTrusted(
			isMainFrame: isMainFrame,
			scheme: scheme,
			host: host,
			port: port,
			frameDocumentURL: frame.flatMap { URL(string: $0) },
			committedDocumentURL: committed.flatMap { URL(string: $0) },
			generationMatches: generation,
			zipMatches: zip,
			activeBundleMatches: bundle
		)
	}

	@Test func clientSideRoutesInTheFragmentAreTheSameDocument() {
		for route in ["#/chat", "#/BountyBoard", "#/settings", "#/", "#", "#/chat?peer=0xabc", "#/settings/legal"] {
			#expect(gate(frame: committed + route), "\(route) is a client-side route of the committed document")
		}
		// The committed URL may itself carry a fragment.
		#expect(gate(frame: committed + "#/chat", committed: committed + "#/"))
		#expect(gate(frame: committed, committed: committed + "#/home"))
	}

	@Test func anotherPathOrQueryIsAnotherDocument() {
		#expect(!gate(frame: "cashtrees-local://localhost/other.html#/chat"))
		#expect(!gate(frame: "cashtrees-local://localhost/index.html/x#/chat"))
		#expect(!gate(frame: committed + "?x=1#/chat"))
		#expect(!gate(frame: committed + "?x=1", committed: committed + "?x=2"))
		#expect(!gate(frame: "cashtrees-local://user@localhost/index.html#/chat"))
		#expect(!gate(frame: "cashtrees-local://localhost:8443/index.html#/chat"))
	}

	@Test func aMissingDocumentIsRefused() {
		#expect(!gate(frame: nil))
		#expect(!gate(frame: committed + "#/chat", committed: nil))
		#expect(!NativeBridgeTrust.sameDocument(nil, nil))
	}

	@Test func otherOriginsAreRefusedEvenWithTheSameFragment() {
		#expect(!gate(frame: "https://beamio.ca/index.html#/chat", committed: "https://beamio.ca/index.html", scheme: "https", host: "beamio.ca"))
		#expect(!gate(frame: "cashtrees-local://evil/index.html#/chat", committed: "cashtrees-local://evil/index.html", host: "evil"))
		#expect(!gate(frame: committed + "#/chat", scheme: "https"))
		#expect(!gate(frame: committed + "#/chat", host: "localhost.evil"))
		#expect(!gate(frame: committed + "#/chat", port: 8443))
		// The frame claims the local document while the committed one is remote: different documents.
		#expect(!gate(frame: committed + "#/chat", committed: "https://localhost/index.html"))
	}

	@Test func aSubFrameIsRefusedOnAnyRoute() {
		#expect(!gate(frame: committed + "#/chat", isMainFrame: false))
		#expect(!gate(frame: committed, isMainFrame: false))
	}

	@Test func generationZipAndActiveBundleStillRefuseOnAnyRoute() {
		for route in ["", "#/chat", "#/BountyBoard"] {
			#expect(!gate(frame: committed + route, generation: false))
			#expect(!gate(frame: committed + route, zip: false))
			#expect(!gate(frame: committed + route, bundle: false))
		}
	}
}
