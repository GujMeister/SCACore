/// Errors thrown during the SCA flow.
///
/// `DefaultSCAService` produces these at specific points:
/// - `.challengeExpired` → `authenticate` entry, challenge failed `isValid` check
/// - `.unsatisfiableChallenge` → not enough distinct categories to meet `minimumFactorsNeeded`
/// - `.verificationFailed` → server rejected a proof (wrong OTP, wrong password)
/// - `.methodNotAvailable` → biometrics requested but hardware unavailable
/// - `.userCancelled` → user backed out of a `UserInteraction` prompt
/// - `.refreshTokenExpired` → `refreshIfNeeded` failed, full SCA restart needed
/// - `.networkError` → `startChallenge` wrapped a transport failure
///
/// Callers typically switch on this to decide whether to retry,
/// restart the flow, or show an error screen.
public enum SCAError: Error, Sendable {
    
    // MARK: - Challenge Phase
    
    /// Challenge's `expiresAt` has passed. Start a new one.
    case challengeExpired
    
    /// Available methods don't cover enough PSD2 categories.
    /// Can happen if biometrics are skipped and no fallback exists.
    case unsatisfiableChallenge
    
    // MARK: - Verification Phase
    
    /// Server rejected the proof — wrong OTP, wrong password, etc.
    /// `attemptsRemaining`: `nil` if the server doesn't report it.
    case verificationFailed(attemptsRemaining: Int?)
    
    /// Requested method can't be used on this device right now
    /// (e.g. biometrics not enrolled).
    case methodNotAvailable(AuthenticationMethod)
    
    // MARK: - User Interaction
    
    /// User dismissed a `UserInteraction` prompt.
    /// The feature should treat this as a soft abort, not a failure.
    case userCancelled
    
    // MARK: - Token Lifecycle
    
    /// Refresh token is expired or revoked.
    /// Caller must restart with `startChallenge` → `authenticate`.
    case refreshTokenExpired
    
    // MARK: - Transport
    
    /// Wraps the underlying network/server error.
    /// Only produced by `startChallenge` currently — see the inconsistency
    /// note below.
    case networkError(Error)
}
