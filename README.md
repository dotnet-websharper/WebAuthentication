# WebSharper Web Authentication API Binding

This repository provides an F# [WebSharper](https://websharper.com/) binding for the [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API), enabling seamless integration of passwordless authentication and secure credential management in WebSharper applications.

## Repository Structure

The repository consists of two main projects:

1. **Binding Project**:

   - Contains the F# WebSharper binding for the Web Authentication API.

2. **Sample Project**:
   - Demonstrates how to use the Web Authentication API with WebSharper syntax.

## Features

- WebSharper bindings for the Web Authentication API.
- Secure authentication using public key credentials.
- Passwordless login support via WebAuthn.
- Enhanced security with biometric and hardware authentication factors.

## Installation and Building

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

## Why Use the Web Authentication API

The Web Authentication API (WebAuthn) enables secure, passwordless authentication using public key cryptography. Key benefits include:

1. **Passwordless Authentication**: Replace traditional passwords with more secure alternatives like biometrics or security keys.
2. **Phishing Resistance**: Public key authentication protects against credential theft.
3. **Strong Security**: Uses cryptographic proof rather than shared secrets for authentication.
4. **Cross-Platform Compatibility**: Works with supported devices and browsers to offer seamless authentication experiences.

**Note:** WebAuthn requires HTTPS and a compatible browser with authentication device support.
