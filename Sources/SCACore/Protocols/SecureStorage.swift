/// Keychain abstraction for all SCA-related persistent data.
///
/// `DefaultSCAService` uses this at multiple points in the flow:
/// - **Start**: `getDeviceId()` + `isDeviceTrusted()` to build `DeviceContext`
/// - **Finish**: `storeAuthenticationToken()` + `storeRefreshToken()` to persist tokens
/// - **Trust prompt**: `markDeviceAsTrusted()` if user opts in after successful SCA
/// - **Refresh**: `clearAuthenticationToken()` + `clearRefreshToken()` on refresh failure
/// - **Sign out**: clears everything
///
/// The app injects either:
/// - A Keychain-backed implementation (production)
/// - An in-memory dictionary (testing/demo)

@MainActor
public protocol SecureStorage: Sendable {
    
    // MARK: - Authentication Tokens
    
    /// Persist the short-lived access token from `AuthenticationResult`.
    func storeAuthenticationToken(_ token: String) async throws
    func getAuthenticationToken() async -> String?
    func clearAuthenticationToken() async
    
    // MARK: - Refresh Tokens
    
    /// Persist the longer-lived refresh token.
    /// Must use Keychain — never UserDefaults.
    func storeRefreshToken(_ token: String) async throws
    func getRefreshToken() async -> String?
    func clearRefreshToken() async
    
    // MARK: - Device Trust
    
    /// Whether Keychain has a non-expired trust record.
    ///
    /// `DefaultSCAService.buildDeviceContext()` reads this to set
    /// `DeviceContext.claimsTrustedStatus` — which is just a hint.
    /// The server verifies independently via `deviceId`.
    func isDeviceTrusted() async -> Bool
    
    /// Write a trust record, typically with a 30-day expiration.
    ///
    /// Called when the user accepts the trust prompt after successful SCA.
    func markDeviceAsTrusted() async throws
    
    func clearDeviceTrust() async
    
    /// Days until trust expires — for settings UI
    /// (e.g. "This device is trusted, 12 days remaining").
    /// `nil` if device is not trusted.
    func getDaysUntilTrustExpiry() async -> Int?
    
    // MARK: - Device Identification
    
    /// Persistent UUID generated on first launch and stored in Keychain.
    /// This is the primary key the server uses for device identity.
    func getDeviceId() async -> String
    
    /// Human-readable device name for display in settings
    /// (e.g. "Luka's iPhone"). `nil` if unavailable.
    func getDeviceName() async -> String?
    
    // MARK: - Token Validity
    
    /// Check if the stored auth token is still within its time-to-live.
    ///
    /// Not used by `DefaultSCAService` directly — it checks
    /// `AuthenticationResult.isValid` instead. Exposed for external
    /// consumers (e.g. HTTP interceptors) that only have access
    /// to storage, not the original result.
    func isTokenValid(ttl: Int) async -> Bool
}
