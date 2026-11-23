import Foundation
import Testing
@testable import CashTrees_iOS

/// Outbound push registration and OTA accept only exact allowlisted https hosts (beamio.ca); the deprecated
/// beamio.app and its subdomains are refused; redirects are followed only on the same allowed host.
/// Synthetic URLs and a URLProtocol stub only: no request leaves the process.
final class OutboundStubProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (Int, [String: String], Data?))?
    nonisolated(unsafe) static var requestURLs: [URL] = []

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        if let url = request.url { Self.requestURLs.append(url) }
        let (status, headers, body) = Self.handler?(request) ?? (500, [:], nil)
        let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
        // 3xx with Location → wasRedirectedTo, so URLSession asks the delegate (follow or stop). The 3xx response is then
        // completed as well: when the delegate refuses (nil), the session returns it to the caller at once instead of
        // waiting for the request timeout; when the delegate follows, this loader is already cancelled.
        if (300..<400).contains(status), let location = headers["Location"], let target = URL(string: location, relativeTo: request.url) {
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if let body { client?.urlProtocol(self, didLoad: body) }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@Suite(.serialized)
struct BeamioOutboundHostsTests {
    private let push = BeamioOutboundHosts.pushRegistrationHosts
    private let body = #"{"synthetic":true}"#
    private static let okJSON = Data(#"{"success":true}"#.utf8)

    private func stubSession(hosts: Set<String>) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [OutboundStubProtocol.self]
        return URLSession(configuration: config, delegate: BeamioOutboundRedirectGuard(hosts: hosts), delegateQueue: nil)
    }

    private func post(_ urlString: String,
                      _ handler: @escaping (URLRequest) -> (Int, [String: String], Data?)) async -> BeamioPushRegistrationHTTP.Outcome {
        OutboundStubProtocol.handler = handler
        OutboundStubProtocol.requestURLs = []
        let session = stubSession(hosts: push)
        return await withCheckedContinuation { continuation in
            BeamioPushRegistrationHTTP.post(urlString: urlString, bodyJson: body, session: session) {
                continuation.resume(returning: $0)
            }
        }
    }

    // MARK: Allowlists

    @Test func allowlistsAreExactNewHostOnly() {
        #expect(BeamioOutboundHosts.pushRegistrationHosts == ["beamio.ca"])
        #expect(BeamioOutboundHosts.otaHosts == ["beamio.ca"])
    }

    @Test func newHostOverHttpsIsAccepted() {
        #expect(BeamioOutboundHosts.allows(URL(string: "https://beamio.ca/api/registerPushDevice"), hosts: push))
        #expect(BeamioOutboundHosts.allows(URL(string: "https://BEAMIO.CA/api/registerPushDevice"), hosts: push))
    }

    @Test func legacyHostAndSubdomainsAreRefused() {
        for raw in ["https://beamio.app/api/registerPushDevice", "https://www.beamio.app/api/registerPushDevice",
                    "https://api.beamio.app/api/registerPushDevice", "https://cashtrees.beamio.app/x",
                    "https://BEAMIO.APP/x"] {
            #expect(!BeamioOutboundHosts.allows(URL(string: raw), hosts: push), "\(raw)")
            #expect(BeamioPushRegistrationHTTP.request(urlString: raw, bodyJson: body) == nil, "\(raw)")
        }
    }

    @Test func nonHttpsAndLookalikesAndUnlistedSubdomainsAreRefused() {
        for raw in ["http://beamio.ca/api/registerPushDevice", "ws://beamio.ca/x", "beamio.ca/api",
                    "https://beamio.ca.evil.example/x", "https://evilbeamio.ca/x", "https://www.beamio.ca/x",
                    "https://biz.beamio.ca/x", "https://beamio.ca:8443/x", "https://user:pw@beamio.ca/x", ""] {
            #expect(!BeamioOutboundHosts.allows(URL(string: raw), hosts: push), "\(raw)")
            #expect(BeamioPushRegistrationHTTP.request(urlString: raw, bodyJson: body) == nil, "\(raw)")
        }
        #expect(!BeamioOutboundHosts.allows(nil, hosts: push))
    }

    @Test func hostSpellingVariantsAreRefused() {
        // Trailing dot, percent-encoded dot, full-width dot (U+FF0E), ideographic full stop (U+3002), and IDN homoglyphs
        // (Cyrillic а U+0430, Greek ο U+03BF) and their punycode forms. None may reach the network from the page string.
        let variants = [
            "https://beamio.ca./api/registerPushDevice",
            "https://BEAMIO.CA./api/registerPushDevice",
            "https://beamio%2eca/api/registerPushDevice",
            "https://beamio%2Eca/api/registerPushDevice",
            "https://beamio\u{FF0E}ca/api/registerPushDevice",
            "https://beamio\u{3002}ca/api/registerPushDevice",
            "https://be\u{0430}mio.ca/api/registerPushDevice",
            "https://beami\u{03BF}.ca/api/registerPushDevice",
            "https://xn--bemio-7ve.ca/api/registerPushDevice",
            "https://beamio.app./api/registerPushDevice",
            "https://beamio%2eapp/api/registerPushDevice",
        ]
        for raw in variants {
            #expect(!BeamioOutboundHosts.allows(rawString: raw, hosts: push), "\(raw)")
            #expect(BeamioOutboundHosts.rebuilt(rawString: raw, hosts: push) == nil, "\(raw)")
            #expect(BeamioPushRegistrationHTTP.request(urlString: raw, bodyJson: body) == nil, "\(raw)")
            // URL-level rule (redirect targets): refused, or—if Foundation itself maps the form—exactly beamio.ca.
            if let url = URL(string: raw), BeamioOutboundHosts.allows(url, hosts: push) {
                #expect(URLComponents(url: url, resolvingAgainstBaseURL: true)?.percentEncodedHost?.lowercased() == "beamio.ca", "\(raw)")
            }
        }
        for raw in ["https://beamio.ca./x", "https://beamio%2eca/x", "https://be\u{0430}mio.ca/x", "https://beamio.app./x"] {
            if let url = URL(string: raw) {
                #expect(!BeamioOutboundHosts.allows(url, hosts: push), "\(raw)")
            }
        }
    }

    @Test func pushRequestIsRebuiltFromCheckedPartsOnly() {
        let raw = "https://BEAMIO.CA/api/registerPushDevice?v=1&x=a%20b#frag"
        let req = BeamioPushRegistrationHTTP.request(urlString: raw, bodyJson: body)
        #expect(req?.url?.absoluteString == "https://beamio.ca/api/registerPushDevice?v=1&x=a%20b")
        #expect(req?.httpMethod == "POST")
        #expect(req?.httpBody == Data(body.utf8))
        #expect(BeamioOutboundHosts.rebuilt(rawString: "https://beamio.ca/api/registerPushDevice", hosts: push)?.absoluteString
                == "https://beamio.ca/api/registerPushDevice")
    }

    @Test func emptyBodyIsRefused() {
        #expect(BeamioPushRegistrationHTTP.request(urlString: "https://beamio.ca/api/registerPushDevice", bodyJson: "") == nil)
    }

    @Test func otaUrlsPassTheOtaList() {
        #expect(BeamioOutboundHosts.allows(CashTreesPWAScheme.remoteUpdateManifestURL, hosts: BeamioOutboundHosts.otaHosts))
        #expect(BeamioOutboundHosts.allows(CashTreesPWAScheme.remoteBundleBaseURL.appendingPathComponent("SilentPassUI-0.0.1.zip"),
                                           hosts: BeamioOutboundHosts.otaHosts))
    }

    @Test func inboundRuleStillRecognisesLegacyButOutboundDoesNot() {
        // Inbound recognition (NDEF block) is unchanged; it is no longer an outbound gate.
        #expect(BeamioHostRules.isBeamioHost("beamio.app"))
        #expect(!BeamioOutboundHosts.allows(URL(string: "https://beamio.app/x"), hosts: push))
    }

    // MARK: Redirect rule

    @Test func redirectRule() {
        let from = URL(string: "https://beamio.ca/api/registerPushDevice")
        #expect(BeamioOutboundHosts.redirectAllowed(from: from, to: URL(string: "https://beamio.ca/api/registerPushDevice/"), hosts: push))
        #expect(!BeamioOutboundHosts.redirectAllowed(from: from, to: URL(string: "https://beamio.app/api/registerPushDevice"), hosts: push))
        #expect(!BeamioOutboundHosts.redirectAllowed(from: from, to: URL(string: "https://www.beamio.app/x"), hosts: push))
        #expect(!BeamioOutboundHosts.redirectAllowed(from: from, to: URL(string: "https://evil.example/x"), hosts: push))
        #expect(!BeamioOutboundHosts.redirectAllowed(from: from, to: URL(string: "http://beamio.ca/x"), hosts: push))
        #expect(!BeamioOutboundHosts.redirectAllowed(from: from, to: nil, hosts: push))
        // Cross-host between two allowed hosts is refused too.
        let two: Set<String> = ["beamio.ca", "other.example"]
        #expect(!BeamioOutboundHosts.redirectAllowed(from: from, to: URL(string: "https://other.example/x"), hosts: two))
        // An original outside the list never allows a redirect.
        #expect(!BeamioOutboundHosts.redirectAllowed(from: URL(string: "https://beamio.app/x"), to: from, hosts: push))
    }

    // MARK: Stubbed requests (no network)

    @Test func acceptedPostReachesOnlyTheNewHost() async {
        let outcome = await post("https://beamio.ca/api/registerPushDevice") { _ in (200, [:], Self.okJSON) }
        #expect(outcome == .init(ok: true, status: 200, error: nil))
        #expect(OutboundStubProtocol.requestURLs.map(\.host) == ["beamio.ca"])
    }

    @Test func legacyTargetSendsNoRequest() async {
        let outcome = await post("https://beamio.app/api/registerPushDevice") { _ in (200, [:], Self.okJSON) }
        #expect(outcome == .init(ok: false, status: 0, error: "invalid_url_or_body"))
        #expect(OutboundStubProtocol.requestURLs.isEmpty)
    }

    @Test func crossHostRedirectToLegacyIsNotFollowed() async {
        let outcome = await post("https://beamio.ca/api/registerPushDevice") { _ in
            (307, ["Location": "https://beamio.app/api/registerPushDevice"], nil)
        }
        #expect(!outcome.ok)
        #expect(outcome.status == 307)
        #expect(OutboundStubProtocol.requestURLs.count == 1, "the redirect must not produce a second request")
        #expect(OutboundStubProtocol.requestURLs.allSatisfy { $0.host == "beamio.ca" })
    }

    @Test func crossHostRedirectToAnotherHostIsNotFollowed() async {
        let outcome = await post("https://beamio.ca/api/registerPushDevice") { _ in
            (302, ["Location": "https://evil.example/collect"], nil)
        }
        #expect(!outcome.ok)
        #expect(OutboundStubProtocol.requestURLs.count == 1)
    }

    @Test func redirectToHttpOnSameHostIsNotFollowed() async {
        let outcome = await post("https://beamio.ca/api/registerPushDevice") { _ in
            (307, ["Location": "http://beamio.ca/api/registerPushDevice"], nil)
        }
        #expect(!outcome.ok)
        #expect(OutboundStubProtocol.requestURLs.count == 1)
    }

    @Test func sameHostHttpsRedirectIsFollowed() async {
        // Allowed case: proves the stub exercises the redirect path, so the refusals above are not vacuous.
        let outcome = await post("https://beamio.ca/api/registerPushDevice") { req in
            if req.url?.path == "/api/registerPushDevice" {
                return (307, ["Location": "https://beamio.ca/api/v2/registerPushDevice"], nil)
            }
            return (200, [:], Self.okJSON)
        }
        #expect(outcome == .init(ok: true, status: 200, error: nil))
        #expect(OutboundStubProtocol.requestURLs.count == 2)
        #expect(OutboundStubProtocol.requestURLs.allSatisfy { $0.host == "beamio.ca" })
    }

    @Test func otaGuardRefusesCrossHostRedirect() async {
        OutboundStubProtocol.handler = { _ in (302, ["Location": "https://beamio.app/app/update.json"], nil) }
        OutboundStubProtocol.requestURLs = []
        let session = stubSession(hosts: BeamioOutboundHosts.otaHosts)
        var request = URLRequest(url: URL(string: "https://beamio.ca/app/update.json")!, timeoutInterval: 10)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let status: Int? = await withCheckedContinuation { continuation in
            session.dataTask(with: request) { _, response, _ in
                continuation.resume(returning: (response as? HTTPURLResponse)?.statusCode)
            }.resume()
        }
        #expect(status != 200)
        #expect(OutboundStubProtocol.requestURLs.count == 1, "the OTA request must not reach the legacy host")
        #expect(OutboundStubProtocol.requestURLs.allSatisfy { $0.host == "beamio.ca" })
    }
}
