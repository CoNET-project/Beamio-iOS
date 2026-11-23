import Testing
@testable import CashTrees_iOS

/// The page console relay only in Debug and QA builds. Unit tests run in a Debug build, so this checks the
/// Debug side and that the switch follows the build; the Release side is checked on the built app by
/// scripts/verify-ios-console-relay-off.sh (no relay script marker in any Mach-O file), also run by the formal packaging gate.
struct CashTreesWebConsoleRelayGateTests {
    @Test func relayFollowsTheBuild() {
        #if DEBUG || BEAMIO_QA
        #expect(CashTreesWebConsoleRelay.relaysPageConsole)
        #expect(CashTreesWebConsoleRelay.injectionScript().contains("__CT_CONSOLE_PROXY_V4__"))
        #else
        #expect(!CashTreesWebConsoleRelay.relaysPageConsole, "a Release build relays no page console text")
        #expect(CashTreesWebConsoleRelay.injectionScript().isEmpty, "a Release build compiles no relay script")
        #endif
    }
}
