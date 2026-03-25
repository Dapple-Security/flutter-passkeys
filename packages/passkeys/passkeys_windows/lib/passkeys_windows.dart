import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:passkeys_platform_interface/passkeys_platform_interface.dart';
import 'package:passkeys_platform_interface/types/types.dart';
import 'package:passkeys_windows/messages.g.dart';

/// The Windows implementation of [PasskeysPlatform].
class PasskeysWindows extends PasskeysPlatform {
  /// The method channel used to interact with the native platform.
  PasskeysWindows({
    @visibleForTesting PasskeysApi? api,
  }) : _api = api ?? PasskeysApi();

  /// Registers this class as the default instance of [PasskeysPlatform]
  static void registerWith() => PasskeysPlatform.instance = PasskeysWindows();

  final PasskeysApi _api;

  @override
  Future<AuthenticateResponseType> authenticate(
    AuthenticateRequestType request,
  ) async {
    final authenticateResponse = await _api.authenticate(
      request.relyingPartyId,
      request.challenge,
      request.timeout,
      request.userVerification,
      request.allowCredentials
          ?.map(
            (e) => AllowCredential(
              type: e.type,
              id: e.id,
              transports: e.transports,
            ),
          )
          .toList(),
      request.preferImmediatelyAvailableCredentials,
      request.extensions != null ? jsonEncode(request.extensions) : null,
    );

    return AuthenticateResponseType(
      id: authenticateResponse.id,
      rawId: authenticateResponse.rawId,
      clientDataJSON: authenticateResponse.clientDataJSON,
      authenticatorData: authenticateResponse.authenticatorData,
      signature: authenticateResponse.signature,
      userHandle: authenticateResponse.userHandle,
      clientExtensionResults:
          authenticateResponse.clientExtensionResults != null
              ? jsonDecode(authenticateResponse.clientExtensionResults!)
                  as Map<String, dynamic>?
              : null,
    );
  }

  @override
  Future<bool> canAuthenticate() async {
    try {
      final r = await _api.canAuthenticate();
      return r;
    } catch (e) {
      return false;
    }
  }

  @override
  Future<RegisterResponseType> register(RegisterRequestType request) async {
    final userArg = User(
      displayName: request.user.displayName,
      name: request.user.name,
      id: request.user.id,
    );
    final relyingPartyArg = RelyingParty(
      name: request.relyingParty.name,
      id: request.relyingParty.id,
    );

    final requestAuthSelectionType = request.authSelectionType;

    AuthenticatorSelection? authSelection;

    if (requestAuthSelectionType != null) {
      authSelection = AuthenticatorSelection(
        authenticatorAttachment:
            requestAuthSelectionType.authenticatorAttachment,
        requireResidentKey: requestAuthSelectionType.requireResidentKey,
        residentKey: requestAuthSelectionType.residentKey,
        userVerification: requestAuthSelectionType.userVerification,
      );
    }

    final registerResponse = await _api.register(
      request.challenge,
      relyingPartyArg,
      userArg,
      authSelection,
      request.pubKeyCredParams
          ?.map((e) => PubKeyCredParam(type: e.type, alg: e.alg))
          .toList(),
      request.timeout,
      request.attestation,
      request.excludeCredentials
          .map((e) => ExcludeCredential(type: e.type, id: e.id))
          .toList(),
      request.extensions != null ? jsonEncode(request.extensions) : null,
    );

    return RegisterResponseType(
      id: registerResponse.id,
      rawId: registerResponse.rawId,
      clientDataJSON: registerResponse.clientDataJSON,
      attestationObject: registerResponse.attestationObject,
      transports: registerResponse.transports.whereType<String>().toList(),
      clientExtensionResults: registerResponse.clientExtensionResults != null
          ? jsonDecode(registerResponse.clientExtensionResults!)
              as Map<String, dynamic>?
          : null,
    );
  }

  @override
  Future<void> cancelCurrentAuthenticatorOperation() =>
      _api.cancelCurrentAuthenticatorOperation();

  @override
  Future<AvailabilityTypeWindows> getAvailability() async {
    final isUserVerifyingPlatformAuthenticatorAvailable =
        await canAuthenticate();

    final hasPasskeySupport = await _api.hasPasskeySupport();

    return AvailabilityTypeWindows(
      hasPasskeySupport: hasPasskeySupport,
      isUserVerifyingPlatformAuthenticatorAvailable:
          isUserVerifyingPlatformAuthenticatorAvailable,
      isNative: true,
    );
  }
}
