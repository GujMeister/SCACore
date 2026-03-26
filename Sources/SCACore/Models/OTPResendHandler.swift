/// Wraps the OTP resend action so it can be passed to UI safely.
///
/// The UI wires this to a "Resend code" button. Under the hood
/// it calls `SCAProvider.sendOTP` with the original method and challenge ID.
///
/// Callable as a function:
/// ```swift
/// try await resend()
/// ```
public struct OTPResendHandler: Sendable {
    
    private let action: @Sendable () async throws -> Void
    
    public init(action: @Sendable @escaping () async throws -> Void) {
        self.action = action
    }
    
    public func callAsFunction() async throws {
        try await action()
    }
}
