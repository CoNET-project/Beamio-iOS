import Foundation
import Testing
@testable import CashTrees_iOS

/// Deep links for the 105 build: generated share and invite links use beamio.ca; incoming links from beamio.ca and the
/// legacy beamio.app are both parsed; any other host is refused. (Owner ruling 2026-11-17.)
struct BeamioDeepLinkHostTests {
    @Test func generatedDefaultLinkIsBeamioCa() {
        #expect(BeamioDeepLink.defaultWebAppURL.absoluteString == "https://beamio.ca/app/")
    }

    @Test func customSchemeOpenGeneratesBeamioCaLink() {
        let resolved = BeamioDeepLink.resolveWebAppURL(from: URL(string: "beamio://open")!)
        #expect(resolved?.absoluteString == "https://beamio.ca/app/")
    }

    @Test func inviteOpenGeneratesBeamioCaLinkWithTheInvite() {
        let invite = "0x" + String(repeating: "ab", count: 20)
        let resolved = BeamioDeepLink.resolveWebAppURL(from: URL(string: "beamio://open?invite=\(invite)")!)
        #expect(resolved?.host == "beamio.ca")
        #expect(resolved?.absoluteString.contains("invite=\(invite)") == true)
    }

    @Test func incomingBeamioCaUniversalLinkIsAccepted() {
        let resolved = BeamioDeepLink.resolveWebAppURL(from: URL(string: "https://beamio.ca/app/?x=1")!)
        #expect(resolved?.host == "beamio.ca")
        #expect(resolved != nil)
    }

    @Test func incomingLegacyBeamioAppLinkIsStillParsed() {
        let resolved = BeamioDeepLink.resolveWebAppURL(from: URL(string: "https://beamio.app/app/?x=1")!)
        #expect(resolved?.host == "beamio.app")
        #expect(resolved != nil)
    }

    @Test func otherHostsAreRefused() {
        #expect(BeamioDeepLink.resolveWebAppURL(from: URL(string: "https://evil.example/app/?x=1")!) == nil)
        #expect(BeamioDeepLink.resolveWebAppURL(from: URL(string: "https://beamio.ca.evil.example/app/?x=1")!) == nil)
        #expect(BeamioDeepLink.resolveWebAppURL(from: URL(string: "http://beamio.ca/app/?x=1")!) == nil)
    }

    @Test func beamioCaAppPathMapsToTheLocalScheme() {
        let remote = URL(string: "https://beamio.ca/app/?x=1")!
        let local = BeamioDeepLink.mapResolvedWebAppURLToLocal(remote)
        #expect(local.scheme == CashTreesPWAScheme.scheme)
        #expect(local.host == CashTreesPWAScheme.host)
    }
}
