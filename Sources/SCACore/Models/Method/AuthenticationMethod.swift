/// (1.1) Building blocks inside every `SCAChallenge`.
///
/// Each method maps to exactly one PSD2 category.
/// The server sends available methods with the challenge →
/// `DefaultSCAService.resolveMethod` picks the best one automatically
/// based on category priority (inherence → knowledge → possession).

public struct AuthenticationMethod: Codable, Sendable, Hashable {
    
    /// Machine identifier used in proof submission (e.g. `"sms_otp"`, `"face_id"`).
    public let identifier: String
    
    /// User-facing label for method selection UI.
    public let displayName: String
    
    /// PSD2 factor category — determines how this method
    /// contributes to the multi-factor requirement.
    public let category: PSD2Category
    
    public init(
        identifier: String,
        displayName: String,
        category: PSD2Category
    ) {
        self.identifier = identifier
        self.displayName = displayName
        self.category = category
    }
}

// MARK: - Standard Methods

public extension AuthenticationMethod {
    
    // Knowledge (something you know)
    
    static let password = AuthenticationMethod(
        identifier: "password",
        displayName: "Password",
        category: .knowledge
    )
    
    static let pin = AuthenticationMethod(
        identifier: "pin",
        displayName: "PIN Code",
        category: .knowledge
    )
    
    // Possession (something you have)
    
    static let smsOTP = AuthenticationMethod(
        identifier: "sms_otp",
        displayName: "SMS Code",
        category: .possession
    )
    
    static let emailOTP = AuthenticationMethod(
        identifier: "email_otp",
        displayName: "Email Code",
        category: .possession
    )
    
    static let totp = AuthenticationMethod(
        identifier: "totp",
        displayName: "Authenticator App",
        category: .possession
    )
    
    // Inherence (something you are)
    
    static let webauthn = AuthenticationMethod(
        identifier: "webauthn",
        displayName: "Face ID / Touch ID",
        category: .inherence
    )
    
    static let faceID = AuthenticationMethod(
        identifier: "face_id",
        displayName: "Face ID",
        category: .inherence
    )
    
    static let touchID = AuthenticationMethod(
        identifier: "touch_id",
        displayName: "Touch ID",
        category: .inherence
    )
}
