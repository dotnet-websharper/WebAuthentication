namespace WebSharper.WebAuthentication

open WebSharper
open WebSharper.JavaScript
open WebSharper.InterfaceGenerator
open WebSharper.CredentialManagement

module Definition =

    let BinaryData = T<ArrayBuffer> + T<DataView>

    module Enum = 
        let Attestation = 
            Pattern.EnumStrings "Attestation" [
                "none"
                "direct"
                "enterprise"
                "indirect"
            ]

        let AuthenticatorAttachment = 
            Pattern.EnumStrings "AuthenticatorAttachment" [
                "platform"
                "cross-platform"
            ]

        let ResidentKey = 
            Pattern.EnumStrings "ResidentKey" [
                "discouraged"
                "preferred"
                "required"
            ]

        let UserVerification = 
            Pattern.EnumStrings "UserVerification" [
                "discouraged"
                "preferred"
                "required"
            ]

        let Transports = 
            Pattern.EnumStrings "Transports" [
                "ble"
                "hybrid"
                "internal"
                "nfc"
                "usb"
            ]

        let Type = 
            Pattern.EnumStrings "Type" [
                "public-key"
            ]

        let Hints = 
            Pattern.EnumStrings "Hints" [
                "security-key"
                "client-device"
                "hybrid"
            ]

        let Format = 
            Pattern.EnumStrings "Format" [
                "packed"
                "tpm"
                "android-key"
                "android-safetynet"
                "fido-u2f"
                "none"
            ]

    let ExcludeCredentialsObject = 
        Pattern.Config "ExcludeCredentialsObject" {
            Required = [
                "id", BinaryData
                "type", Enum.Type.Type
            ]
            Optional = [
                "transports", !| Enum.Transports
            ]
        }

    let ExcludeCredentialsObjectBase64 = 
        Pattern.Config "ExcludeCredentialsObjectBase64" {
            Required = [
                "id", T<string>
                "type", Enum.Type.Type
            ]
            Optional = [
                "transports", !| Enum.Transports
            ]
        }

    let PubKeyCredParamsObject = 
        Pattern.Config "PubKeyCredParamsObject" {
            Required = [
                "alg", T<int>
                "type", Enum.Type.Type
            ]
            Optional = []
        }

    let RpObject = 
        Pattern.Config "RpObject" {
            Required = [
                "name", T<string>
            ]
            Optional = [
                "id", T<string>
            ]
        }

    let UserObject = 
        Pattern.Config "UserObject" {
            Required = [
                "displayName", T<string>
                "id", BinaryData
                "name", T<string>
            ]
            Optional = []
        }

    let UserObjectBase64 = 
        Pattern.Config "UserObjectBase64" {
            Required = [
                "displayName", T<string>
                "id", T<string>
                "name", T<string>
            ]
            Optional = []
        }

    let AuthenticatorSelectionObject = 
        Pattern.Config "AuthenticatorSelectionObject" {
            Required = []
            Optional = [
                "authenticatorAttachment", Enum.AuthenticatorAttachment.Type
                "requireResidentKey", T<bool>
                "residentKey", Enum.ResidentKey.Type
                "userVerification", Enum.UserVerification.Type
            ]
        }

    let PublicKeyCredentialCreationOptionsCommon =
        Pattern.Config "PublicKeyCredentialCreationOptionsCommon" {
            Required = [
                "pubKeyCredParams", !| PubKeyCredParamsObject
                "rp", RpObject.Type
            ]
            Optional = [
                "attestation", Enum.Attestation.Type
                "attestationFormats", !| T<string>
                "authenticatorSelection", AuthenticatorSelectionObject.Type                     
                "extensions", T<obj>
                "timeout", T<int>
                "hint", !| Enum.Hints
            ]
        }

    let PublicKeyCredentialCreationOptions =
        Pattern.Config "PublicKeyCredentialCreationOptions" {
            Required = [
                "challenge", BinaryData
                "user", UserObject.Type
            ]
            Optional = [
                "excludeCredentials", !| ExcludeCredentialsObject
            ]
        }
        |=> Inherits PublicKeyCredentialCreationOptionsCommon

    let PublicKeyCredentialCreationOptionsBase64 =
        Pattern.Config "PublicKeyCredentialCreationOptionsBase64" {
            Required = [
                "challenge", T<string>
                "user", UserObjectBase64.Type
            ]
            Optional = [
                "excludeCredentials", !| ExcludeCredentialsObjectBase64
            ]
        }
        |=> Inherits PublicKeyCredentialCreationOptionsCommon

    let AllowCredentialsObject = 
        Pattern.Config "AllowCredentialsObject" {
            Required = [
                "id", BinaryData
                "transports", !| Enum.Transports
                "type", Enum.Type.Type
            ]
            Optional = []
        }

    let AllowCredentialsObjectBase64 = 
        Pattern.Config "AllowCredentialsObjectBase64" {
            Required = [
                "id", T<string>
                "transports", !| Enum.Transports
                "type", Enum.Type.Type
            ]
            Optional = []
        }

    let PublicKeyCredentialRequestOptionsCommon = 
        Pattern.Config "PublicKeyCredentialRequestOptionsCommon" {
            Required = []
            Optional = [
                "extensions", T<obj>
                "hints", !| Enum.Hints
                "rpId", T<string>
                "timeout", T<int>
                "userVerification", Enum.UserVerification.Type
            ]
        }

    let PublicKeyCredentialRequestOptions = 
        Pattern.Config "PublicKeyCredentialRequestOptions" {
            Required = [
                "challenge", BinaryData
            ]
            Optional = [
                "allowCredentials", AllowCredentialsObject.Type
            ]
        }
        |=> Inherits PublicKeyCredentialRequestOptionsCommon

    let PublicKeyCredentialRequestOptionsBase64 = 
        Pattern.Config "PublicKeyCredentialRequestOptionsBase64" {
            Required = [
                "challenge", T<string>
            ]
            Optional = [
                "allowCredentials", AllowCredentialsObjectBase64.Type
            ]
        }
        |=> Inherits PublicKeyCredentialRequestOptionsCommon

    let AuthenticatorResponse = 
        Pattern.Config "AuthenticatorResponse" {
            Required = []
            Optional = [
                "clientDataJSON", BinaryData
            ]
        }

    let AuthenticatorAssertionResponse = 
        Class "AuthenticatorAssertionResponse"
        |=> Inherits AuthenticatorResponse
        |+> Instance [
            "authenticatorData" =? BinaryData
            "signature" =? BinaryData
            "userHandle" =? BinaryData
        ]

    let AttestationObject =
        Pattern.Config "AttestationObject" {
            Required = [
                "authData", BinaryData
                "fmt", Enum.Format.Type
                "attStmt", T<obj>
            ]
            Optional = []
        }

    let AuthenticatorAttestationResponse = 
        Class "AuthenticatorAttestationResponse"
        |=> Inherits AuthenticatorResponse
        |+> Instance [
            "attestationObject" =? BinaryData

            "getAuthenticatorData" => T<unit> ^-> BinaryData
            "getPublicKey" => T<unit> ^-> BinaryData
            "getPublicKeyAlgorithm" => T<unit> ^-> T<int>
            "getTransports" => T<unit> ^-> !| Enum.Transports 
        ]

    let PublicKeyCredentialJSON =
        Pattern.Config "PublicKeyCredentialJSON" {
            Required = [
                "id", T<string>
                "rawId", T<string>
                "type", T<string>
                "clientExtensionResults", !| T<string>
                "response", T<obj>
            ]
            Optional = [
                "authenticatorAttachment", T<string>
                
            ]
        }

    let PublicKeyCredential = 
        Class "PublicKeyCredential"
        |=> Inherits T<Credential>
        |+> Static [
            "isConditionalMediationAvailable" => T<unit> ^-> T<Promise<bool>>
            "isUserVerifyingPlatformAuthenticatorAvailable" => T<unit> ^-> T<Promise<bool>>
            "parseCreationOptionsFromJSON" => PublicKeyCredentialCreationOptionsBase64?options ^-> PublicKeyCredentialCreationOptions
            "parseRequestOptionsFromJSON" => PublicKeyCredentialRequestOptionsBase64?options ^-> PublicKeyCredentialRequestOptions
        ]
        |+> Instance [
            "authenticatorAttachment" =? T<string>
            "id" =? T<string>
            "rawId" =? BinaryData
            "response" =? AuthenticatorAttestationResponse + AuthenticatorAssertionResponse

            "getClientExtensionResults" => T<unit> ^-> T<obj>
            "toJSON" => T<unit> ^-> PublicKeyCredentialJSON
        ]

    let Assembly =
        Assembly [
            Namespace "WebSharper.WebAuthentication" [
                Enum.Format
                Enum.Hints
                Enum.Type
                Enum.Transports
                Enum.UserVerification
                Enum.ResidentKey
                Enum.AuthenticatorAttachment
                Enum.Attestation

                AttestationObject
                AuthenticatorAssertionResponse
                AuthenticatorResponse
                PublicKeyCredentialRequestOptionsBase64
                PublicKeyCredentialRequestOptions
                PublicKeyCredentialRequestOptionsCommon
                AllowCredentialsObjectBase64
                AllowCredentialsObject
                PublicKeyCredentialCreationOptionsBase64
                PublicKeyCredentialCreationOptions
                PublicKeyCredentialCreationOptionsCommon
                AuthenticatorSelectionObject
                UserObjectBase64
                UserObject
                RpObject
                PubKeyCredParamsObject
                ExcludeCredentialsObjectBase64
                ExcludeCredentialsObject
                PublicKeyCredentialJSON
                AuthenticatorAttestationResponse
                PublicKeyCredential
            ]
        ]

[<Sealed>]
type Extension() =
    interface IExtension with
        member ext.Assembly =
            Definition.Assembly

[<assembly: Extension(typeof<Extension>)>]
do ()
