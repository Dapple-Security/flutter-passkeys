import AuthenticationServices
import LocalAuthentication
import Foundation
import Combine

#if os(iOS)
import Flutter
#elseif os(macOS)
import FlutterMacOS
#else
#error("Unsupported platform.")
#endif

protocol Cancellable {
    func cancel()
}

@available(macOS 13.5, iOS 16.0, *)
public class PasskeysPlugin: NSObject, FlutterPlugin, PasskeysApi {
    var inFlightController: Cancellable?
    let lock = NSLock()
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = PasskeysPlugin()
        // Workaround for https://github.com/flutter/flutter/issues/118103.
        #if os(iOS)
                let messenger = registrar.messenger()
        #else
                let messenger = registrar.messenger
        #endif
        PasskeysApiSetup.setUp(binaryMessenger: messenger, api: instance)
    }
    
    func canAuthenticate() throws -> Bool {
        return LocalAuth.shared.canAuthenticate()
    }
    
    func hasBiometrics() throws -> Bool {
        return LocalAuth.shared.hasBiometrics()
    }
    
    func getFacetID(completion: @escaping (Result<String, Error>) -> Void) {
        completion(.success(""))
    }
    
    func register(
        challenge: String,
        relyingParty: RelyingParty,
        user: User,
        excludeCredentials: [CredentialType],
        pubKeyCredValues: [Int64],
        canBePlatformAuthenticator: Bool = true,
        canBeSecurityKey: Bool = true,
        residentKeyPreference: String?,
        attestationPreference: String?,
        extensions: String?,
        completion: @escaping (Result<RegisterResponse, Error>) -> Void
    ) {
        guard (try? canAuthenticate()) == true else {
            completion(.failure(CustomErrors.deviceNotSupported))
            return
        }
        
        guard let decodedChallenge = Data.fromBase64Url(challenge) else {
            completion(.failure(CustomErrors.decodingChallenge))
            return
        }

        guard let decodedUserId = Data.fromBase64Url(user.id) else {
            completion(.failure(CustomErrors.decodingChallenge))
            return
        }
        
        var requests: [ASAuthorizationRequest] = []
        let rp = relyingParty.id
        
        if(canBePlatformAuthenticator){
            // Create a platform (on‑device) registration request.
            let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rp)
            let platformRequest = platformProvider.createCredentialRegistrationRequest(
                challenge: decodedChallenge,
                name: user.name,
                userID: decodedUserId
            )
            

            if #available(iOS 17.4, *) {
                let excluded = parseCredentials(credentials: excludeCredentials)
                platformRequest.excludedCredentials = excluded
            }
            
            requests.append(platformRequest)
        }
        
        if(canBeSecurityKey){
            // Create an external (security key) registration request.
            let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rp)
            let externalRequest = securityKeyProvider.createCredentialRegistrationRequest(
                challenge: decodedChallenge,
                displayName: user.name,   // displayName as provided by the new API
                name: user.name,
                userID: decodedUserId
            )

            switch residentKeyPreference {
            case .some("preferred"):
                externalRequest.residentKeyPreference = .preferred
            case .some("required"):
                externalRequest.residentKeyPreference = .required
            default:
                break
            }

            switch attestationPreference {
            case .some("none"):
                externalRequest.attestationPreference = .none
            case .some("indirect"):
                externalRequest.attestationPreference = .indirect
            case .some("direct"):
                externalRequest.attestationPreference = .direct
            default:
                break
            }
            
            
            if #available(iOS 17.4, *) {
                let excludedSecurityKeys = parseSecurityKeyCredentials(credentials: excludeCredentials)
                externalRequest.excludedCredentials = excludedSecurityKeys
            }
            
            externalRequest.credentialParameters = pubKeyCredValues.map { rawValue in
                let intValue = Int(rawValue)
                
                return ASAuthorizationPublicKeyCredentialParameters(
                    algorithm: ASCOSEAlgorithmIdentifier(rawValue: intValue)
                )
            }
            
            requests.append(externalRequest)
        }
        
        // Parse extensions JSON
        var extensionsDict: [String: Any]?
        if let extensionsJson = extensions,
           let data = extensionsJson.data(using: .utf8),
           let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            extensionsDict = parsed
        }
        
        // Apply largeBlob extension to platform requests if available
        if #available(iOS 17.0, macOS 14.0, *) {
            if let largeBlobExt = extensionsDict?["largeBlob"] as? [String: Any] {
                for request in requests {
                    if let platformRequest = request as? ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest {
                        if largeBlobExt["support"] as? String == "required" {
                            platformRequest.largeBlob = ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.supportRequired
                        } else if largeBlobExt["support"] as? String == "preferred" {
                            platformRequest.largeBlob = ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.supportPreferred
                        }
                    }
                }
            }
        }
        
        // Apply PRF extension to platform registration requests if available
        if #available(iOS 18.0, macOS 15.0, *) {
            if let prfExt = extensionsDict?["prf"] as? [String: Any] {
                for request in requests {
                    if let platformRequest = request as? ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest {
                        if let eval = prfExt["eval"] as? [String: Any],
                           let firstB64 = eval["first"] as? String,
                           let firstData = Data.fromBase64Url(firstB64) {
                            let secondData = (eval["second"] as? String).flatMap { Data.fromBase64Url($0) }
                            let saltValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues.saltInput1(firstData, saltInput2: secondData)
                            platformRequest.prf = .inputValues(saltValues)
                        } else {
                            platformRequest.prf = .checkForSupport
                        }
                    }
                }
            }
        }
        
        func wrappedCompletion(result: Result<RegisterResponse, Error>) {
            lock.unlock()
            completion(result)
        }
        
        let con = RegisterController(completion: wrappedCompletion, extensions: extensionsDict)
        con.run(requests: requests)
        inFlightController = con
    }
    
    func authenticate(
        relyingPartyId: String,
        challenge: String,
        conditionalUI: Bool,
        allowedCredentials: [CredentialType],
        preferImmediatelyAvailableCredentials: Bool,
        extensions: String?,
        completion: @escaping (Result<AuthenticateResponse, Error>) -> Void
    ) {
        guard (try? canAuthenticate()) == true else {
            completion(.failure(CustomErrors.deviceNotSupported))
            return
        }
        
        guard let decodedChallenge = Data.fromBase64Url(challenge) else {
            completion(.failure(CustomErrors.decodingChallenge))
            return
        }
        
        var requests: [ASAuthorizationRequest] = []
        
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: relyingPartyId)
        let platformRequest = platformProvider.createCredentialAssertionRequest(challenge: decodedChallenge)
        platformRequest.allowedCredentials = parseCredentials(credentials: allowedCredentials)
        requests.append(platformRequest)
        
        // We should not show the security key flow when preferImmediatelyAvailable is set to true
        // Also skip security key requests when using conditional UI, which doesn't support them
        if !preferImmediatelyAvailableCredentials && !conditionalUI {
            let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: relyingPartyId)
            let externalRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: decodedChallenge)
            externalRequest.allowedCredentials = parseSecurityKeyCredentials(credentials: allowedCredentials)
            requests.append(externalRequest)
        }
        
        // Parse extensions JSON
        var extensionsDict: [String: Any]?
        if let extensionsJson = extensions,
           let data = extensionsJson.data(using: .utf8),
           let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            extensionsDict = parsed
        }
        
        // Apply largeBlob extension to platform assertion requests if available
        if #available(iOS 17.0, macOS 14.0, *) {
            if let largeBlobExt = extensionsDict?["largeBlob"] as? [String: Any] {
                for request in requests {
                    if let platformRequest = request as? ASAuthorizationPlatformPublicKeyCredentialAssertionRequest {
                        if let readData = largeBlobExt["read"] as? Bool, readData {
                            platformRequest.largeBlob = ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.read
                        } else if let writeData = largeBlobExt["write"] as? String,
                                  let writeBytes = Data.fromBase64Url(writeData) {
                            platformRequest.largeBlob = ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.write(writeBytes)
                        }
                    }
                }
            }
        }
        
        // Apply PRF extension to platform assertion requests if available
        if #available(iOS 18.0, macOS 15.0, *) {
            if let prfExt = extensionsDict?["prf"] as? [String: Any],
               let eval = prfExt["eval"] as? [String: Any],
               let firstB64 = eval["first"] as? String,
               let firstData = Data.fromBase64Url(firstB64) {
                let secondData = (eval["second"] as? String).flatMap { Data.fromBase64Url($0) }
                let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues.saltInput1(firstData, saltInput2: secondData)

                var perCredentialValues: [Data: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues]?
                if let evalByCredential = prfExt["evalByCredential"] as? [String: [String: Any]] {
                    perCredentialValues = [:]
                    for (credId, salts) in evalByCredential {
                        if let credIdData = Data.fromBase64Url(credId),
                           let saltFirstB64 = salts["first"] as? String,
                           let saltFirstData = Data.fromBase64Url(saltFirstB64) {
                            let saltSecondData = (salts["second"] as? String).flatMap { Data.fromBase64Url($0) }
                            perCredentialValues?[credIdData] = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues.saltInput1(saltFirstData, saltInput2: saltSecondData)
                        }
                    }
                }

                let prfInput = ASAuthorizationPublicKeyCredentialPRFAssertionInput.inputValues(
                    inputValues, perCredentialInputValues: perCredentialValues
                )

                for request in requests {
                    if let platformRequest = request as? ASAuthorizationPlatformPublicKeyCredentialAssertionRequest {
                        platformRequest.prf = prfInput
                    }
                }
            }
        }
        
        let con = AuthenticateController(completion: completion, extensions: extensionsDict)
        con.run(requests: requests, conditionalUI: conditionalUI, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials)
        inFlightController = con
    }
    
    func cancelCurrentAuthenticatorOperation(completion: @escaping (Result<Void, Error>) -> Void) {
        inFlightController?.cancel()
        completion(.success(()))
    }
    
    private func parseCredentials(credentials: [CredentialType]) -> [ASAuthorizationPlatformPublicKeyCredentialDescriptor] {
        return credentials.compactMap { credential in
            guard let credentialData = Data.fromBase64Url(credential.id) else {
                return nil
            }
            return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialData)
        }
    }
    
    private func parseSecurityKeyCredentials(credentials: [CredentialType]) -> [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor] {
        return credentials.compactMap { credential in
            guard let credentialData = Data.fromBase64Url(credential.id) else {
                return nil
            }
            
            let parsedTransports: [ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport] = credential.transports.compactMap { transport in
                switch transport {
                case "nfc":
                    return .nfc
                case "usb":
                    return .usb
                case "bluetooth":
                    return .bluetooth
                default:
                    return nil
                }
            }
            
            return ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                credentialID: credentialData,
                transports: parsedTransports
            )
        }
    }
}

open class LocalAuth: NSObject {
    public static let shared = LocalAuth()
    private override init() {}
    
    var laContext = LAContext()
    
    func canAuthenticate() -> Bool {
        if #unavailable(iOS 16.0) {
            return false
        }
        return true
    }
    
    func hasBiometrics() -> Bool {
        var error: NSError?
        return laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
}

struct PublicKeyCredentialCreateResponse: Codable {
    let challenge: String
    let user: User
    let rp: RP

    struct RP: Codable {
        let name: String
        let id: String
    }

    struct User: Codable {
        let name: String
        let displayName: String
        let id: String
    }
}

public extension Data {
    /// Same as Data(base64Encoded:), but adds padding automatically (if missing).
    static func fromBase64(_ encoded: String) -> Data? {
        var encoded = encoded
        let remainder = encoded.count % 4
        if remainder > 0 {
            encoded = encoded.padding(
                toLength: encoded.count + 4 - remainder,
                withPad: "=",
                startingAt: 0
            )
        }
        return Data(base64Encoded: encoded)
    }

    static func fromBase64Url(_ encoded: String) -> Data? {
        let base64String = base64UrlToBase64(base64Url: encoded)
        return fromBase64(base64String)
    }

    private static func base64UrlToBase64(base64Url: String) -> String {
        return base64Url.replacingOccurrences(of: "-", with: "+")
                         .replacingOccurrences(of: "_", with: "/")
    }
}

public extension String {
    static func fromBase64(_ encoded: String) -> String? {
        if let data = Data.fromBase64(encoded) {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }
}

extension Data {
    func toBase64URL() -> String {
        var result = self.base64EncodedString()
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }
}

import CryptoKit

extension SymmetricKey {
    func toBase64URL() -> String {
        return withUnsafeBytes { Data(Array($0)).toBase64URL() }
    }
}
