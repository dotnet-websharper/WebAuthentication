# WebSharper Web Authentication API Binding

This repository provides an F# [WebSharper](https://websharper.com/) binding for the [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API), enabling strong, passwordless authentication with public-key credentials in WebSharper applications.

## Repository Structure

The repository consists of two main projects:

1. **Binding Project**:

   - Contains the F# WebSharper binding for the Web Authentication API.

2. **Sample Project**:

   - Demonstrates how to use the Web Authentication API with WebSharper syntax.

   - Includes a GitHub Pages demo: [View Demo](https://dotnet-websharper.github.io/WebAuthentication/)

## Installation

To use this package in your WebSharper project, add the NuGet package:

```bash
   dotnet add package WebSharper.WebAuthentication
```

## Building

### Prerequisites

- [.NET SDK](https://dotnet.microsoft.com/download) installed on your machine.

### Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/dotnet-websharper/WebAuthentication.git
   cd WebAuthentication
   ```

2. Build the Binding Project:

   ```bash
   dotnet build WebSharper.WebAuthentication/WebSharper.WebAuthentication.fsproj
   ```

3. Build and Run the Sample Project:

   ```bash
   cd WebSharper.WebAuthentication.Sample
   dotnet build
   dotnet run
   ```

## Example Usage

The following example demonstrates how to register and authenticate a user using Web Authentication in a WebSharper project:

```fsharp
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
```

## Notes

- Web Authentication (WebAuthn) is a powerful standard that supports passwordless authentication.
- Requires HTTPS context in production environments.
- Compatible with modern browsers that support `navigator.credentials.create()` and `navigator.credentials.get()` APIs.
