//
//  BeamioOutboundHosts.swift
//  CashTrees_iOS
//
//  Outbound rule for native requests whose target the page supplies or a server redirect may change.
//  Exact host allowlists, https only, no explicit port, no user info. Separate from `BeamioHostRules`, which is an
//  inbound recognition rule (NDEF navigation block) and must not be used to allow an outbound request.
//  The deprecated host beamio.app and its subdomains are in no outbound list.
//

import Foundation

enum BeamioOutboundHosts {
    /// Push registration: the frozen PWA posts to `https://beamio.ca/api/registerPushDevice`. No subdomain is used.
    static let pushRegistrationHosts: Set<String> = ["beamio.ca"]

    /// OTA manifest and bundle downloads (`CashTreesPWAScheme.remoteUpdateManifestURL` / `remoteBundleBaseURL`).
    static let otaHosts: Set<String> = ["beamio.ca"]

    /// True when `url` is https on one of `hosts` (exact, case-insensitive), with no explicit port and no user info.
    /// The host is compared in its percent-encoded form and the whole URL must be ASCII, so `beamio%2eca`, a trailing
    /// dot (`beamio.ca.`) and non-ASCII (IDN homoglyph) hosts never match.
    static func allows(_ url: URL?, hosts: Set<String>) -> Bool {
        guard let url,
              url.absoluteString.allSatisfy(\.isASCII),
              let c = URLComponents(url: url, resolvingAgainstBaseURL: true)
        else { return false }
        return componentsAllowed(c, hosts: hosts)
    }

    /// The raw page string must itself be ASCII (a full-width dot or homoglyph is refused before any parsing maps it).
    static func allows(rawString: String, hosts: Set<String>) -> Bool {
        guard rawString.allSatisfy(\.isASCII), let c = URLComponents(string: rawString) else { return false }
        return componentsAllowed(c, hosts: hosts)
    }

    private static func componentsAllowed(_ c: URLComponents, hosts: Set<String>) -> Bool {
        guard c.scheme?.lowercased() == "https",
              let host = c.percentEncodedHost?.lowercased(), hosts.contains(host),
              c.port == nil,
              c.user == nil, c.password == nil
        else { return false }
        return true
    }

    /// A fresh URL from the checked parts only: https + allowed host + path + query (no user info, port or fragment).
    /// nil unless the raw string passes `allows(rawString:hosts:)` and the rebuilt URL passes `allows(_:hosts:)`.
    static func rebuilt(rawString: String, hosts: Set<String>) -> URL? {
        guard allows(rawString: rawString, hosts: hosts), let parsed = URLComponents(string: rawString),
              let host = parsed.percentEncodedHost?.lowercased()
        else { return nil }
        var c = URLComponents()
        c.scheme = "https"
        c.percentEncodedHost = host
        c.percentEncodedPath = parsed.percentEncodedPath
        c.percentEncodedQuery = parsed.percentEncodedQuery
        guard let url = c.url, allows(url, hosts: hosts) else { return nil }
        return url
    }

    /// A redirect is followed only when both the original request and the target are allowed and the target stays
    /// on the same host. Anything else (another host, http, a host outside the list) is not followed.
    static func redirectAllowed(from original: URL?, to target: URL?, hosts: Set<String>) -> Bool {
        guard allows(original, hosts: hosts), allows(target, hosts: hosts),
              original?.host?.lowercased() == target?.host?.lowercased()
        else { return false }
        return true
    }
}

/// Redirect guard for a session bound to one outbound allowlist. Returning nil stops at the 3xx response, which the
/// caller treats as a failure.
final class BeamioOutboundRedirectGuard: NSObject, URLSessionTaskDelegate {
    let hosts: Set<String>

    init(hosts: Set<String>) {
        self.hosts = hosts
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        let original = task.originalRequest?.url ?? response.url
        completionHandler(BeamioOutboundHosts.redirectAllowed(from: original, to: request.url, hosts: hosts) ? request : nil)
    }
}

/// Native POST of the page-signed `registerPushDevice` JSON. The page supplies the URL; only the push allowlist passes.
enum BeamioPushRegistrationHTTP {
    struct Outcome: Equatable {
        let ok: Bool
        let status: Int
        let error: String?
    }

    /// Dedicated session: redirects only on the same allowed host (no `URLSession.shared` default following).
    static let session: URLSession = URLSession(
        configuration: .ephemeral,
        delegate: BeamioOutboundRedirectGuard(hosts: BeamioOutboundHosts.pushRegistrationHosts),
        delegateQueue: nil
    )

    /// Validates the target and body before any request; nil when either is refused.
    static func request(urlString: String, bodyJson: String) -> URLRequest? {
        // The request is built from a URL rebuilt from the checked parts, not from the object parsed out of the page string.
        guard let url = BeamioOutboundHosts.rebuilt(rawString: urlString, hosts: BeamioOutboundHosts.pushRegistrationHosts),
              let data = bodyJson.data(using: .utf8), !data.isEmpty
        else { return nil }
        var req = URLRequest(url: url, timeoutInterval: 14)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = data
        return req
    }

    /// Completion runs on the session's delegate queue. Success = 2xx and JSON `success == true`.
    static func post(urlString: String, bodyJson: String, session: URLSession = session,
                     completion: @escaping (Outcome) -> Void) {
        guard let req = request(urlString: urlString, bodyJson: bodyJson) else {
            completion(Outcome(ok: false, status: 0, error: "invalid_url_or_body"))
            return
        }
        session.dataTask(with: req) { data, response, error in
            if let error {
                completion(Outcome(ok: false, status: 0, error: error.localizedDescription))
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            var success = false
            if status >= 200, status < 300, let data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                success = json["success"] as? Bool == true
            }
            completion(Outcome(ok: success, status: status, error: nil))
        }.resume()
    }
}
