/// Observable flow state for UI implementations of `UserInteraction`.
///
/// Not used by `DefaultSCAService` directly — this is a convenience
/// for coordinators that drive SwiftUI views off a single published state.
///
/// Example:
/// ```swift
/// @Published var step: SCAFlowStep = .idle
///
/// func requestKnowledgeFactor(method: AuthenticationMethod) async throws -> String {
///     step = .enterKnowledge(method)
///     return try await waitForUserInput()
/// }
/// ```
public enum SCAFlowStep: Equatable {
    case idle
    case selectMethod([AuthenticationMethod], ChallengeReason)
    case enterKnowledge(AuthenticationMethod)
    case enterOTP(AuthenticationMethod)
    case promptTrust
    case verifying
    case error(String)
    
    public static func == (lhs: SCAFlowStep, rhs: SCAFlowStep) -> Bool {
        switch (lhs, rhs) {
        case (.idle, .idle),
             (.selectMethod, .selectMethod),
             (.enterKnowledge, .enterKnowledge),
             (.enterOTP, .enterOTP),
             (.promptTrust, .promptTrust),
             (.verifying, .verifying),
             (.error, .error):
            return true
        default:
            return false
        }
    }
}
