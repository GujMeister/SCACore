/// Network boundary for all SCA operations.
///
/// `DefaultSCAService` calls these methods at each server touchpoint:
/// - `startChallenge` → (1) kick off the flow, get requirements
/// - `sendOTP` → (2) trigger OTP delivery before showing the input screen
/// - `verify` → (2→3) submit each proof, get partial/complete status
/// - `refreshAuthentication` → (3+) silently renew an expired token
/// - `logout` → tear down server session on sign-out
///
/// The app injects either:
/// - A real implementation backed by URLSession (production)
/// - A mock with configurable responses (testing/demo)
public protocol SCAProvider: Sendable {
    
    // MARK: - Challenge
    
    /// Request a new SCA challenge for a protected operation.
    ///
    /// The server inspects `context` (amount, recipient, etc.) to apply
    /// risk-based decisions — a $10 transfer may get lighter requirements
    /// than a $10,000 one.
    ///
    /// - Returns: `SCAChallenge` describing available methods and requirements
    func startChallenge(
        for operation: ChallengeReason,
        context: ChallengeContext?
    ) async throws -> SCAChallenge
    
    // MARK: - Verification
    
    /// Submit a single authentication proof.
    ///
    /// The server is the source of truth for challenge progress:
    /// - `.partial(satisfiedCategories:)` → more factors needed, keep looping
    /// - `.complete(AuthenticationResult)` → all done, here's the token
    ///
    /// Called once per factor in the `authenticate` loop.
    func verify(proof: AuthenticationProof) async throws -> VerificationStepResult
    
    /// Trigger OTP delivery to the user's registered contact.
    ///
    /// Called by the service *before* `UserInteraction.requestPossessionFactor`,
    /// so the code is already in flight when the input screen appears.
    /// Also wired into `OTPResendHandler` for the "Resend code" button.
    func sendOTP(method: AuthenticationMethod, challengeId: String) async throws
    
    // MARK: - Token Lifecycle
    
    /// Exchange a refresh token for a fresh access token.
    ///
    /// Called by `refreshIfNeeded` when the access token has expired
    /// but the refresh token is still valid.
    /// On failure, the service clears stored tokens → full SCA restart.
    func refreshAuthentication(using refreshToken: String) async throws -> AuthenticationResult
    
    /// Notify the server that the user is logging out.
    ///
    /// Server revokes tokens and clears session state.
    /// Called by `signOut()` before clearing local storage.
    func logout() async throws
}
