/// UI coordination point for the SCA flow.
///
/// `DefaultSCAService.authenticate(challenge:)` calls into this protocol
/// at every point where user interaction is needed:
/// - `resolveMethod` → `selectAuthenticationMethod` (rare — only when multiple methods share a category)
/// - `collectCredential` → `requestKnowledgeFactor` or `requestPossessionFactor`
/// - Post-authentication → `promptToTrustDevice` (if device isn't already trusted)
/// - Error paths → `showError`
///
/// All methods are `async` — the service suspends until the UI resolves.
/// Throw `UserInteractionError.cancelled` from any method to abort the flow
/// (the service maps this to `SCAError.userCancelled`).
@MainActor
public protocol UserInteraction: Sendable {
    
    // MARK: - Method Selection
    
    /// Let the user pick between methods in the same PSD2 category.
    ///
    /// Only called when a single category has multiple options
    /// (e.g. both SMS and email OTP under possession).
    /// When there's only one method per category, the service auto-picks.
    ///
    /// - Parameters:
    ///   - methods: Options within a single category (always ≥ 2)
    ///   - reason: Drives UI messaging ("Confirm payment" vs "Log in")
    /// - Throws: `UserInteractionError.cancelled` → service throws `SCAError.userCancelled`
    func selectAuthenticationMethod(
        from methods: [AuthenticationMethod],
        reason: ChallengeReason
    ) async throws -> AuthenticationMethod
    
    // MARK: - Credential Collection
    
    /// Show password or PIN entry screen.
    ///
    /// Called when the resolved method is a knowledge factor.
    /// The returned string is sent as `AuthenticationProof.credential`.
    ///
    /// - Parameter method: `.password` or `.pin` — use to show the right input type
    func requestKnowledgeFactor(method: AuthenticationMethod) async throws -> String
    
    /// Show OTP entry screen.
    ///
    /// The service triggers OTP delivery *before* calling this,
    /// so the code is already on its way when the screen appears.
    ///
    /// - Parameters:
    ///   - method: `.smsOTP`, `.emailOTP`, or `.totp` — drives "Check your SMS" vs "Check your email" messaging
    ///   - resend: Callable the UI can wire to a "Resend code" button.
    ///     Calls `SCAProvider.sendOTP` under the hood.
    func requestPossessionFactor(
        method: AuthenticationMethod,
        resend: OTPResendHandler
    ) async throws -> String
    
    // MARK: - Device Trust
    
    /// Prompt the user to trust this device after successful SCA.
    ///
    /// Only called when `DeviceContext.claimsTrustedStatus` is `false`.
    /// If the user accepts, `SecureStorage.markDeviceAsTrusted()` is called
    /// and future SCA flows skip one factor (possession covered implicitly).
    ///
    /// - Returns: `true` if user opts in
    func promptToTrustDevice() async -> Bool
    
    // MARK: - Error Display
    
    /// Surface an error to the user.
    ///
    /// Called on unrecoverable failures during the flow.
    /// The implementation decides presentation (alert, inline banner, etc.).
    func showError(_ error: Error) async
}

/// Errors thrown from `UserInteraction` methods.
///
/// The service catches these and maps them:
/// - `.cancelled` → `SCAError.userCancelled` (flow aborts)
/// - `.timeout` → `SCAError.userCancelled` (same effect)
/// - `.invalidInput` → typically retried before surfacing
public enum UserInteractionError: Error {
    case cancelled
    case timeout
    case invalidInput
}
