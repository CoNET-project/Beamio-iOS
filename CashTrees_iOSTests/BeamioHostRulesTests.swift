import Testing
@testable import CashTrees_iOS

/// Beamio host rule for the NDEF block and the native POST proxy (105): exact host or a true subdomain only.
struct BeamioHostRulesTests {
    @Test func exactHostsAndSubdomainsMatch() {
        #expect(BeamioHostRules.isBeamioHost("beamio.ca"))
        #expect(BeamioHostRules.isBeamioHost("www.beamio.ca"))
        #expect(BeamioHostRules.isBeamioHost("BEAMIO.CA"))
        #expect(BeamioHostRules.isBeamioHost("beamio.app"))
        #expect(BeamioHostRules.isBeamioHost("www.beamio.app"))
    }

    @Test func lookalikesDoNotMatch() {
        #expect(!BeamioHostRules.isBeamioHost("beamio.ca.evil.example"))
        #expect(!BeamioHostRules.isBeamioHost("evilbeamio.ca"))
        #expect(!BeamioHostRules.isBeamioHost("beamio.app.evil.example"))
        #expect(!BeamioHostRules.isBeamioHost("example.com"))
        #expect(!BeamioHostRules.isBeamioHost(""))
    }
}
