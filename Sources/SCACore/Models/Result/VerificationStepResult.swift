/// Intermediate result from `SCAProvider.verify(proof:)`.
///
/// The server is the single source of truth for challenge progress.
/// After each proof submission:
/// - `.partial` → more factors needed, loop continues
/// - `.complete` → all done, `DefaultSCAService` stores tokens and returns
///
/// This exists because gathering a single factor doesn't earn a token.
/// Only the final verification that meets `minimumFactorsNeeded` does.
public enum VerificationStepResult: Sendable {
    
    /// Proof accepted, but the challenge isn't fully satisfied yet.
    /// `satisfiedCategories` reflects the server's running tally —
    /// the service unions this with implicit categories (device trust)
    /// to decide what's still needed.
    case partial(satisfiedCategories: Set<PSD2Category>)
    
    /// All factors satisfied — here's the scoped token.
    /// Next step → `DefaultSCAService` stores tokens, prompts for
    /// device trust if needed, and returns this to the caller.
    case complete(AuthenticationResult)
}
