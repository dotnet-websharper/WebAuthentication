namespace WebSharper.WebAuthentication

open WebSharper
open WebSharper.JavaScript

[<JavaScript; AutoOpen>]
module Extensions =
    type Navigator with
        [<Inline "$this.credentials">]
        member this.Credentials with get(): CredentialsContainer = X<CredentialsContainer>
