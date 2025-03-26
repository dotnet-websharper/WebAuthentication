namespace WebSharper.WebAuthentication.Sample

open WebSharper
open WebSharper.JavaScript
open WebSharper.UI
open WebSharper.UI.Client
open WebSharper.UI.Templating
open WebSharper.WebAuthentication

[<JavaScript>]
module Client =
    // Define the connection to the HTML template
    type IndexTemplate = Template<"wwwroot/index.html", ClientLoad.FromDocument>

    // Encode string to ArrayBuffer using TextEncoder
    let strToBuf(str: string) = 
        let textEncoder = JS.Eval("new TextEncoder()")
        textEncoder?encode(str) |> As<ArrayBuffer>

    let savedCredentialId = Var.Create (Unchecked.defaultof<ArrayBuffer>)

    // Registration logic using WebAuthn
    let register() = promise {
        let pubKeyCredParams = PubKeyCredParamsObject(
            ``type`` = CredentialType.Public_key,
            alg = -7
        )

        let publicKeyCreate = PublicKeyCredentialCreationOptions(
            challenge = strToBuf("random-challenge"),
            rp = RpObject(name = "My Demo App"),
            user = UserInfo(
                id = strToBuf("user-id"),
                name = "user@example.com",
                displayName = "Test User"
                ),
            pubKeyCredParams = [|pubKeyCredParams|]
        )

        try
            let! cred = JS.Window.Navigator?credentials?create({|publicKey = publicKeyCreate|}) |> As<Promise<PublicKeyCredential>>

            savedCredentialId.Value <- cred.RawId |> As<ArrayBuffer>
            JS.Alert("✅ Registered successfully!")
            Console.Log("Credential:", cred)
        with e ->
            JS.Alert("❌ Registration failed")
            Console.Error(e)
    }

    // Login logic using saved credentials
    let login() = promise {
        if isNull savedCredentialId.Value then
            JS.Alert("❗ Register first!")
        else
            let allowCredentials = AllowCredentialsObject(
                id = savedCredentialId.Value,
                ``type`` = CredentialType.Public_key
            )

            let publicKeyGet = PublicKeyCredentialRequestOptions(
                challenge = strToBuf("random-challenge"),
                AllowCredentials = [|allowCredentials|]
            )

            try
                let! assertion = JS.Window.Navigator?credentials?get({|publicKey = publicKeyGet|}) |> As<Promise<PublicKeyCredential>>

                JS.Alert("✅ Login successful!")
                Console.Log("Assertion:", assertion)
            with e ->
                JS.Alert("❌ Login failed")
                Console.Error(e)
    }

    [<SPAEntryPoint>]
    let Main () =
        IndexTemplate.Main()
            .RegisterBtn(fun _ -> 
                async { 
                    do! register () |> Promise.AsAsync 
                } 
                |> Async.StartImmediate
            )
            .LoginBtn(fun _ -> 
                async { 
                    do! login () |> Promise.AsAsync 
                } 
                |> Async.StartImmediate
            )
            .Doc()
        |> Doc.RunById "main"