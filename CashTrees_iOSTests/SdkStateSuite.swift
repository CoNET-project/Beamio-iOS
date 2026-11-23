import Testing

/// The parent of the suites that share the SDK's process-wide state: the PWA sync sequence ledger, the wallet test memory,
/// the account pointer, the native session gate and the native key store. Swift Testing runs top-level suites in parallel,
/// so these suites are nested here: a serialized parent runs its children one after another.
@Suite(.serialized)
enum SdkStateSuite {}
