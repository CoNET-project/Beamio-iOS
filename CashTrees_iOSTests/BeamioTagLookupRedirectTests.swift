import Foundation
import Testing
@testable import CashTrees_iOS

/// search-users lookup for the incoming-call @tag (105). Redirects are followed only to https on beamio.ca.
/// Stubbed with URLProtocol; no network. Covers: normal @tag, cross-host redirect refused (no second request),
/// http redirect refused, and no-data / non-2xx / network error → no @tag and no crash.
final class SearchUsersStubProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (Int, [String: String], Data?, Error?))?
    nonisolated(unsafe) static var requestURLs: [URL] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        if let url = request.url { Self.requestURLs.append(url) }
        let (status, headers, body, error) = Self.handler?(request) ?? (500, [:], nil, nil)
        if let error {
            client?.urlProtocol(self, didFailWithError: error)
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        // A 3xx with a Location is a redirect: report it through wasRedirectedTo so URLSession runs the delegate's
        // willPerformHTTPRedirection decision (follow with the new request, or stop with nil).
        if (300..<400).contains(status), let location = headers["Location"], let target = URL(string: location, relativeTo: request.url) {
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if let body { client?.urlProtocol(self, didLoad: body) }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@Suite(.serialized)
struct BeamioTagLookupRedirectTests {
    private let address = "0x" + String(repeating: "ab", count: 20)

    private func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [SearchUsersStubProtocol.self]
        return URLSession(configuration: config, delegate: SearchUsersRedirectGuard(), delegateQueue: nil)
    }

    private func lookup(_ handler: @escaping (URLRequest) -> (Int, [String: String], Data?, Error?)) async -> String? {
        SearchUsersStubProtocol.handler = handler
        SearchUsersStubProtocol.requestURLs = []
        return await withCheckedContinuation { continuation in
            BeamioTagAddressLookup.fetchExactTag(for: address, session: session()) { tag in
                continuation.resume(returning: tag)
            }
        }
    }

    private static func json(_ address: String, username: String) -> Data {
        try! JSONSerialization.data(withJSONObject: ["results": [["address": address, "username": username]]])
    }

    @Test func normalResponseShowsTheTag() async {
        let addr = address
        let tag = await lookup { _ in (200, [:], Self.json(addr, username: "alice"), nil) }
        #expect(tag == BeamioIncomingCallPayload.normalizedBeamioTag("alice"))
        #expect(tag != nil)
        #expect(SearchUsersStubProtocol.requestURLs.count == 1)
        #expect(SearchUsersStubProtocol.requestURLs.first?.host == "beamio.ca")
    }

    @Test func redirectToAnotherHostIsRefusedAndNotFollowed() async {
        let tag = await lookup { _ in (302, ["Location": "https://evil.example/api/search-users"], nil, nil) }
        #expect(tag == nil)
        #expect(SearchUsersStubProtocol.requestURLs.count == 1, "the wallet address must not be sent to a second host")
        #expect(SearchUsersStubProtocol.requestURLs.allSatisfy { $0.host == "beamio.ca" })
    }

    @Test func redirectToHttpIsRefused() async {
        let tag = await lookup { _ in (302, ["Location": "http://beamio.ca/api/search-users"], nil, nil) }
        #expect(tag == nil)
        #expect(SearchUsersStubProtocol.requestURLs.count == 1)
        #expect(SearchUsersStubProtocol.requestURLs.allSatisfy { $0.scheme == "https" })
    }

    @Test func redirectToAnotherBeamioCaHttpsPathIsFollowed() async {
        // The allowed case: a redirect to https://beamio.ca on another path is followed (second request), and its 200
        // body shows the @tag. This proves the stub really exercises the redirect path (the refusals above are not vacuous).
        let addr = address
        let tag = await lookup { req in
            if req.url?.path == "/api/search-users" {
                return (302, ["Location": "https://beamio.ca/api/search-users-v2?keyward=x"], nil, nil)
            }
            return (200, [:], Self.json(addr, username: "bob"), nil)
        }
        #expect(tag == BeamioIncomingCallPayload.normalizedBeamioTag("bob"))
        #expect(SearchUsersStubProtocol.requestURLs.count == 2, "the allowed redirect must produce a second request")
        #expect(SearchUsersStubProtocol.requestURLs.last?.host == "beamio.ca")
    }

    @Test func redirectToBeamioCaOverHttpsIsTheOnlyAllowedRule() {
        #expect(BeamioTagAddressLookup.redirectAllowed(URL(string: "https://beamio.ca/api/search-users")))
        #expect(BeamioTagAddressLookup.redirectAllowed(URL(string: "https://BEAMIO.ca/x")))
        #expect(!BeamioTagAddressLookup.redirectAllowed(URL(string: "https://beamio.ca.evil.example/x")))
        #expect(!BeamioTagAddressLookup.redirectAllowed(URL(string: "http://beamio.ca/x")))
        #expect(!BeamioTagAddressLookup.redirectAllowed(URL(string: "https://beamio.app/x")))
        #expect(!BeamioTagAddressLookup.redirectAllowed(nil))
    }

    @Test func noDataOrNon2xxOrTimeoutShowsNoTagAndDoesNotCrash() async {
        #expect(await lookup { _ in (200, [:], nil, nil) } == nil)
        #expect(await lookup { _ in (500, [:], Self.json(self.address, username: "x"), nil) } == nil)
        #expect(await lookup { _ in (0, [:], nil, URLError(.timedOut)) } == nil)
        #expect(await lookup { _ in (200, [:], Data("not json".utf8), nil) } == nil)
    }

    @Test func invalidAddressIsRejectedBeforeAnyRequest() async {
        SearchUsersStubProtocol.requestURLs = []
        let tag = await withCheckedContinuation { continuation in
            BeamioTagAddressLookup.fetchExactTag(for: "not-an-address", session: session()) { continuation.resume(returning: $0) }
        }
        #expect(tag == nil)
        #expect(SearchUsersStubProtocol.requestURLs.isEmpty)
    }
}
