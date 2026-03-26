/// Main orchestration point for the entire SCA flow.
///
/// A feature that needs authentication does three things:
/// ```swift
/// // 1. Get requirements
/// let challenge = try await sca.startChallenge(for: .payment, context: context)
///
/// // 2. Run the multi-factor flow
/// let result = try await sca.authenticate(challenge: challenge)
///
/// // 3. Attach token to the protected request
/// request.setValue(result.authorizationHeader, forHTTPHeaderField: "Authorization")
/// ```
///
/// Later, when the token expires:
/// ```swift
/// let fresh = try await sca.refreshIfNeeded(result: storedResult)
/// ```
///
/// The default implementation (`DefaultSCAService`) handles method resolution,
/// credential collection, proof submission, token storage, and device trust
/// internally — features don't manage any of that.
@MainActor
public protocol SCAService {
    
    // MARK: - Core Flow
    
    /// (1) Request a challenge describing what authentication is required.
    func startChallenge(
        for reason: ChallengeReason,
        context: ChallengeContext?
    ) async throws -> SCAChallenge
    
    /// (1→3) Execute the full multi-factor flow for a challenge.
    ///
    /// Internally: checks device trust → resolves methods → collects credentials
    /// → submits proofs → stores tokens → optionally prompts for device trust.
    /// Returns only when all factors are satisfied or throws on failure.
    func authenticate(challenge: SCAChallenge) async throws -> AuthenticationResult
    
    /// Revoke tokens server-side, then clear local storage.
    func signOut() async
    
    // MARK: - Token Management
    
    /// Silently renew an expired token using its refresh token.
    ///
    /// Returns the original result if still valid.
    /// Throws `.refreshTokenExpired` if renewal fails → full SCA restart needed.
    func refreshIfNeeded(result: AuthenticationResult) async throws -> AuthenticationResult
    
    /// Convenience check: is this result still valid *and* scoped for this operation?
    func isAuthorized(_ result: AuthenticationResult, for reason: ChallengeReason) -> Bool
    
    // MARK: - Device & Method Availability
    
    /// Whether a specific method is usable on this device right now.
    func canUseMethod(_ method: AuthenticationMethod) async -> Bool
    
    /// Whether the current device has implicit possession factor.
    ///
    /// Exposed for settings screens ("This device is trusted, 12 days remaining").
    /// Features don't need to check this before calling `authenticate` —
    /// the service accounts for it internally.
    var isDeviceTrusted: Bool { get async }
    
    // MARK: - Device Trust Management
    
    /// Mark current device as trusted. For settings screen use —
    /// the service handles this internally during `authenticate`.
    func trustCurrentDevice() async throws
    
    /// Remove trust from current device. For settings screen "Remove trust" action.
    func removeTrust() async
}

/// Default implementation orchestrating four injected dependencies:
/// - `SCAProvider` — network calls (or mock)
/// - `SecureStorage` — Keychain (or in-memory mock)
/// - `BiometricProvider` — Face ID / Touch ID (or mock)
/// - `UserInteraction` — UI prompts (or scripted mock)
@MainActor
public final class DefaultSCAService: SCAService {
    
    nonisolated private let provider: SCAProvider
    nonisolated private let storage: SecureStorage
    nonisolated private let biometrics: BiometricProvider
    nonisolated private let ui: UserInteraction
    
    public init(
        provider: SCAProvider,
        storage: SecureStorage,
        biometrics: BiometricProvider,
        ui: UserInteraction
    ) {
        self.provider = provider
        self.storage = storage
        self.biometrics = biometrics
        self.ui = ui
    }
    
    // MARK: - Core Flow
    
    public func startChallenge(
        for reason: ChallengeReason,
        context: ChallengeContext?
    ) async throws -> SCAChallenge {
        do {
            return try await provider.startChallenge(for: reason, context: context)
        } catch {
            throw SCAError.networkError(error)
        }
    }
    
    public func authenticate(challenge: SCAChallenge) async throws -> AuthenticationResult {
        // ── Step 1: Validate challenge isn't expired ──
        print("SCA [1]: Validating challenge...")
        guard challenge.isValid else { throw SCAError.challengeExpired }
        print("SCA [1]: Challenge valid ✅")
        
        // ── Step 2: Build device context from secure storage ──
        print("SCA [2]: Building device context...")
        let deviceContext = await buildDeviceContext()
        let deviceTrusted = deviceContext.claimsTrustedStatus
        print("SCA [2]: Device trusted = \(deviceTrusted)")
        
        // ── Step 3: Determine what's already covered implicitly ──
        let implicitCategories: Set<PSD2Category> = deviceTrusted ? [.possession] : []
        print("SCA [3]: Implicit categories = \(implicitCategories)")
        
        // ── Step 4: Filter to methods the user must explicitly satisfy ──
        let actionableMethods = challenge.availableMethods
            .filter { !implicitCategories.contains($0.category) }
        print("SCA [4]: Actionable methods = \(actionableMethods.map(\.identifier))")
        
        let actionableCategories = Set(actionableMethods.map { $0.category })
        let explicitFactorsNeeded = max(0, challenge.minimumFactorsNeeded - implicitCategories.count)
        print("SCA [5]: Need \(explicitFactorsNeeded) explicit factors from categories: \(actionableCategories)")
        
        guard actionableCategories.count >= explicitFactorsNeeded else {
            print("SCA [5]: ❌ Not enough categories")
            throw SCAError.unsatisfiableChallenge
        }
        print("SCA [5]: Can satisfy ✅")
        
        // ── Step 6: Factor collection loop ──
        //
        // Each iteration: resolve best method → collect credential → verify with server.
        // Server responds with `.partial` (keep going) or `.complete` (done).
        // Biometric failure doesn't abort — we skip inherence and try next category.
        
        var collectedProofs: [AuthenticationProof] = []
        var satisfiedCategories: Set<PSD2Category> = implicitCategories
        var skippedCategories: Set<PSD2Category> = []
        var loopCount = 0
        
        while satisfiedCategories.count < challenge.minimumFactorsNeeded {
            loopCount += 1
            print("SCA [6]: --- Loop \(loopCount) ---")
            print("SCA [6]: Satisfied so far = \(satisfiedCategories)")
            
            let remainingMethods = actionableMethods
                .filter { !satisfiedCategories.contains($0.category) }
                .filter { !skippedCategories.contains($0.category) }
            print("SCA [6]: Remaining methods = \(remainingMethods.map(\.identifier))")
            
            guard !remainingMethods.isEmpty else {
                print("SCA [6]: ❌ No remaining methods")
                throw SCAError.unsatisfiableChallenge
            }
            
            // ── Step 7: Pick the best method ──
            print("SCA [7]: Resolving method...")
            let selectedMethod = try await resolveMethod(
                from: remainingMethods,
                reason: challenge.reason
            )
            print("SCA [7]: Resolved → \(selectedMethod.identifier) (\(selectedMethod.category))")
            
            // ── Step 8: Collect credential from user ──
            print("SCA [8]: Collecting credential for \(selectedMethod.identifier)...")
            
            let credential: String
            do {
                credential = try await collectCredential(
                    for: selectedMethod,
                    challenge: challenge
                )
            } catch SCAError.userCancelled {
                // User cancelled — bubble up, flow is done
                throw SCAError.userCancelled
            } catch where selectedMethod.category == .inherence {
                // Biometric failed — skip inherence, try next category
                print("SCA [8]: ⚠️ Biometric failed/cancelled — skipping inherence, falling back")
                skippedCategories.insert(.inherence)
                continue
            }
            
            print("SCA [8]: Credential collected ✅")
            
            // ── Step 9: Submit proof to server ──
            let proof = AuthenticationProof(
                challengeId: challenge.challengeId,
                method: selectedMethod,
                credential: credential,
                deviceContext: deviceContext
            )
            
            print("SCA [9]: Verifying proof...")
            let stepResult = try await verifyProof(proof)
            collectedProofs.append(proof)
            
            switch stepResult {
            case .partial(let serverCategories):
                satisfiedCategories = serverCategories.union(implicitCategories)
                print("SCA [9]: Partial ✅ — server confirms categories: \(serverCategories)")
                print("SCA [9]: Combined with implicit = \(satisfiedCategories)")
                
            case .complete(let result):
                // ── Step 10: Store tokens ──
                print("SCA [10]: All factors satisfied! Storing tokens...")
                try await storeTokens(from: result)
                print("SCA [10]: Tokens stored ✅")
                
                // ── Step 11: Optionally prompt for device trust ──
                if !deviceTrusted {
                    print("SCA [11]: Prompting for device trust...")
                    let wantsTrust = await ui.promptToTrustDevice()
                    print("SCA [11]: User wants trust = \(wantsTrust)")
                    if wantsTrust {
                        try await storage.markDeviceAsTrusted()
                    }
                }
                
                print("SCA [12]: ✅ Authentication complete!")
                return result
            }
        }
        
        print("SCA: ❌ Fell through loop — should never happen")
        throw SCAError.unsatisfiableChallenge
    }
    
    public func signOut() async {
        do {
            try await provider.logout()
        } catch {
            // Best-effort — still clear local state even if server call fails
            print("SCA: Server logout failed: \(error) — clearing local state anyway")
        }
        
        await storage.clearAuthenticationToken()
        await storage.clearRefreshToken()
        await storage.clearDeviceTrust()
        
        print("SCA: Signed out ✅")
    }
    
    // MARK: - Token Management
    
    public func refreshIfNeeded(result: AuthenticationResult) async throws -> AuthenticationResult {
        if result.isValid { return result }
        
        guard let refreshToken = result.refreshToken else {
            throw SCAError.refreshTokenExpired
        }
        
        do {
            let newResult = try await provider.refreshAuthentication(using: refreshToken)
            try await storeTokens(from: newResult)
            return newResult
        } catch {
            await storage.clearAuthenticationToken()
            await storage.clearRefreshToken()
            throw SCAError.refreshTokenExpired
        }
    }
    
    public func isAuthorized(_ result: AuthenticationResult, for reason: ChallengeReason) -> Bool {
        result.isValid && result.scope == reason
    }
    
    // MARK: - Device & Method Availability
    
    public func canUseMethod(_ method: AuthenticationMethod) async -> Bool {
        switch method.category {
        case .inherence:
            return await biometrics.isAvailable
        case .knowledge, .possession:
            return true
        }
    }
    
    public var isDeviceTrusted: Bool {
        get async {
            await storage.isDeviceTrusted()
        }
    }
    
    // MARK: - Device Trust Management
    
    public func trustCurrentDevice() async throws {
        try await storage.markDeviceAsTrusted()
    }
    
    public func removeTrust() async {
        await storage.clearDeviceTrust()
    }
}

// MARK: - Private Helpers

private extension DefaultSCAService {
    
    /// Build `DeviceContext` from secure storage.
    /// Called once at the start of `authenticate` — the context is reused
    /// for every proof in that flow.
    func buildDeviceContext() async -> DeviceContext {
        let deviceId = await storage.getDeviceId()
        let isTrusted = await storage.isDeviceTrusted()
        return DeviceContext(
            deviceId: deviceId,
            claimsTrustedStatus: isTrusted
        )
    }
    
    /// Persist both tokens from an `AuthenticationResult`.
    /// Extracted to avoid duplication between `authenticate` and `refreshIfNeeded`.
    func storeTokens(from result: AuthenticationResult) async throws {
        try await storage.storeAuthenticationToken(result.authenticationToken)
        if let refresh = result.refreshToken {
            try await storage.storeRefreshToken(refresh)
        }
    }
    
    /// Pick the best method from the remaining options.
    ///
    /// Priority: inherence → knowledge → possession.
    /// Within a category: single method auto-picks, multiple methods ask the user.
    /// Biometrics are checked for availability before committing to inherence.
    func resolveMethod(
        from methods: [AuthenticationMethod],
        reason: ChallengeReason
    ) async throws -> AuthenticationMethod {
        let byCategory = Dictionary(grouping: methods) { $0.category }
        let priorityOrder: [PSD2Category] = [.inherence, .knowledge, .possession]
        
        print("RESOLVE: Available categories = \(byCategory.keys.map { $0.rawValue })")
        
        for category in priorityOrder {
            guard let methodsInCategory = byCategory[category],
                  !methodsInCategory.isEmpty else { continue }
            
            // Skip inherence if hardware isn't available
            if category == .inherence {
                guard await biometrics.isAvailable else {
                    print("RESOLVE: Biometrics unavailable, skipping inherence")
                    continue
                }
            }
            
            // Single method — auto-pick, no user interaction needed
            if methodsInCategory.count == 1 {
                print("RESOLVE: ✅ Auto-picking → \(methodsInCategory[0].identifier)")
                return methodsInCategory[0]
            }
            
            // Multiple methods in same category — ask user to choose
            print("RESOLVE: Multiple methods in \(category.rawValue) — asking user...")
            do {
                let selected = try await ui.selectAuthenticationMethod(
                    from: methodsInCategory,
                    reason: reason
                )
                print("RESOLVE: ✅ User picked → \(selected.identifier)")
                return selected
            } catch let error as UserInteractionError {
                switch error {
                case .cancelled, .timeout:
                    throw SCAError.userCancelled
                case .invalidInput:
                    // Shouldn't happen on a picker, but treat as cancel
                    throw SCAError.userCancelled
                }
            }
        }
        
        throw SCAError.unsatisfiableChallenge
    }
    
    /// Collect the raw credential for a given method.
    ///
    /// - Knowledge: shows password/PIN screen via `UserInteraction`
    /// - Possession: triggers OTP delivery first, then shows input screen
    /// - Inherence: prompts biometric via `BiometricProvider`
    ///
    /// Throws `SCAError.userCancelled` on cancel/timeout.
    /// Biometric failures throw generic errors — the caller decides
    /// whether to skip inherence or abort.
    func collectCredential(
        for method: AuthenticationMethod,
        challenge: SCAChallenge
    ) async throws -> String {
        switch method.category {
        case .knowledge:
            do {
                return try await ui.requestKnowledgeFactor(method: method)
            } catch let error as UserInteractionError {
                switch error {
                case .cancelled, .timeout:
                    throw SCAError.userCancelled
                case .invalidInput:
                    // TODO: Could re-prompt here instead of aborting
                    throw SCAError.userCancelled
                }
            }
            
        case .possession:
            do {
                try await provider.sendOTP(method: method, challengeId: challenge.challengeId)
            } catch {
                throw SCAError.networkError(error)
            }
            
            let resend = OTPResendHandler { [provider] in
                try await provider.sendOTP(method: method, challengeId: challenge.challengeId)
            }
            
            do {
                return try await ui.requestPossessionFactor(method: method, resend: resend)
            } catch let error as UserInteractionError {
                switch error {
                case .cancelled, .timeout:
                    throw SCAError.userCancelled
                case .invalidInput:
                    // TODO: Could re-prompt here instead of aborting
                    throw SCAError.userCancelled
                }
            }
            
        case .inherence:
            guard await biometrics.isAvailable else {
                throw SCAError.methodNotAvailable(method)
            }
            let success = try await biometrics.authenticate(reason: challenge.reason.rawValue)
            guard success else {
                throw SCAError.verificationFailed(attemptsRemaining: nil)
            }
            return "biometric_success"
        }
    }
    
    /// Submit proof to server, wrapping transport errors consistently.
    func verifyProof(_ proof: AuthenticationProof) async throws -> VerificationStepResult {
        do {
            return try await provider.verify(proof: proof)
        } catch let error as SCAError {
            throw error
        } catch {
            throw SCAError.networkError(error)
        }
    }
}
