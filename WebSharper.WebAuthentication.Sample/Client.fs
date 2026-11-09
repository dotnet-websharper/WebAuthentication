namespace WebSharper.WebAuthentication.Sample

open WebSharper
open WebSharper.JavaScript
open WebSharper.UI
open WebSharper.UI.Notation
open WebSharper.UI.Client
open WebSharper.UI.Templating
open WebSharper.WebAuthentication

[<JavaScript>]
module Client =
    // The template is loaded from the DOM, so editing index.html and refreshing
    // the browser is enough; a rebuild is only needed when holes change.
    type IndexTemplate = Template<"wwwroot/index.html", ClientLoad.FromDocument>

    // ----- UI state ----------------------------------------------------------
    let status = Var.Create "Ready. Register a credential to get started."
    let credentialId = Var.Create "—"
    let capabilities = Var.Create "Checking browser support…"

    // The raw id of the last registered credential, reused for login.
    let savedCredentialId = Var.Create (As<ArrayBuffer> null)

    // ----- Capability probing ------------------------------------------------
    // navigator.credentials comes from the Extensions assembly. WebAuthn is only
    // exposed in a secure context (HTTPS or localhost) and not by every browser,
    // so we probe instead of assuming it exists.
    let credentials = JS.Window.Navigator.Credentials

    let hasCredentials =
        let c: obj = JS.Window.Navigator?credentials
        not (isNull c) && not (c ===. JS.Undefined)

    let hasWebAuthn =
        let c: obj = JS.Global?PublicKeyCredential
        not (isNull c) && not (c ===. JS.Undefined)

    // ----- Helpers -----------------------------------------------------------
    // A fresh random byte buffer.
    let private randomBytes (n: int) =
        JS.Eval(sprintf "crypto.getRandomValues(new Uint8Array(%d)).buffer" n) |> As<ArrayBuffer>

    // A random challenge. A real server must generate the challenge, store it
    // for the user, and verify it when the assertion comes back.
    let private randomChallenge () = randomBytes 32

    let private toHex (buffer: ArrayBuffer) =
        let bytes = Uint8Array(buffer)
        Seq.init bytes.Length (fun i -> bytes.Get(i))
        |> Seq.map (fun b -> sprintf "%02x" b)
        |> String.concat ""

    let private rawIdOf (cred: PublicKeyCredential) =
        cred.RawId |> As<ArrayBuffer>

    // ----- Register ----------------------------------------------------------
    let register () =
        promise {
            try
                if not hasCredentials then
                    status := "navigator.credentials is not available. Serve the page over HTTPS or localhost."
                else
                    let parameters =
                        PubKeyCredParamsObject(
                            alg = -7,
                            ``type`` = CredentialType.Public_key
                        )

                    let creationOptions =
                        PublicKeyCredentialCreationOptions(
                            challenge = randomChallenge(),
                            rp = RpObject(name = "WebSharper WebAuthn Demo"),
                            user =
                                UserInfo(
                                    id = randomBytes 16,
                                    name = "demo@example.com",
                                    displayName = "Demo User"
                                ),
                            pubKeyCredParams = [| parameters |]
                        )

                    creationOptions.Attestation <- Attestation.None

                    let authenticatorSelection = AuthenticatorSelectionObject()
                    authenticatorSelection.AuthenticatorAttachment <- AuthenticatorAttachment.Platform
                    authenticatorSelection.ResidentKey <- ResidentKey.Preferred
                    authenticatorSelection.UserVerification <- UserVerification.Preferred
                    creationOptions.AuthenticatorSelection <- authenticatorSelection

                    let options = CredentialCreationOptions(publicKey = creationOptions)
                    let! credential = credentials.Create(options)

                    savedCredentialId := rawIdOf credential
                    credentialId := toHex (rawIdOf credential)
                    status := "Registered a public-key credential."
            with ex ->
                Console.Error("Registration failed:", ex)
                status := "Registration failed: " + ex.Message
        }

    // ----- Login -------------------------------------------------------------
    let login () =
        promise {
            try
                if not hasCredentials then
                    status := "navigator.credentials is not available. Serve the page over HTTPS or localhost."
                elif isNull savedCredentialId.Value then
                    status := "Register a credential first."
                else
                    let requestOptions = PublicKeyCredentialRequestOptions(challenge = randomChallenge())
                    requestOptions.AllowCredentials <-
                        [|
                            AllowCredentialsObject(
                                id = savedCredentialId.Value,
                                ``type`` = CredentialType.Public_key
                            )
                        |]
                    requestOptions.UserVerification <- UserVerification.Preferred

                    let options = CredentialRequestOptions()
                    options.PublicKey <- requestOptions

                    let! assertion = credentials.Get(options)

                    credentialId := toHex (rawIdOf assertion)
                    status := "Authentication succeeded."
            with ex ->
                Console.Error("Authentication failed:", ex)
                status := "Authentication failed: " + ex.Message
        }

    // ----- Browser support ---------------------------------------------------
    let detectCapabilities () =
        promise {
            if not hasWebAuthn then
                capabilities := "WebAuthn (PublicKeyCredential) is not available in this browser."
            else
                try
                    let! platform =
                        PublicKeyCredential.IsUserVerifyingPlatformAuthenticatorAvailable()

                    let! conditional =
                        PublicKeyCredential.IsConditionalMediationAvailable()

                    capabilities :=
                        (if platform then
                             "Platform authenticator: available"
                         else
                             "Platform authenticator: not available")
                        + " · "
                        + (if conditional then
                               "Conditional mediation: available"
                           else
                               "Conditional mediation: not available")
                with ex ->
                    Console.Error("Capability probe failed:", ex)
                    capabilities := "Browser support could not be determined."
        }

    [<SPAEntryPoint>]
    let Main () =
        if not hasCredentials then
            status := "navigator.credentials is not available. Use a modern browser over HTTPS or localhost."
            capabilities := "WebAuthn is unavailable."

        async {
            do! detectCapabilities () |> Promise.AsAsync
        }
        |> Async.StartImmediate

        IndexTemplate.Main()
            .register(fun _ -> register () |> ignore)
            .login(fun _ -> login () |> ignore)
            .status(status.V)
            .credentialId(credentialId.V)
            .capabilities(capabilities.V)
            .Doc()
        |> Doc.RunById "main"
