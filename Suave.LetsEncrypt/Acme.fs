module internal Suave.LetsEncrypt.Acme

open Certes
open Certes.Acme
open Certes.Pkcs
open System.IO
open System.Security.Cryptography.X509Certificates
open Org.BouncyCastle.OpenSsl
open Org.BouncyCastle.Pkcs
open Org.BouncyCastle.Crypto

type KeyAuthorization = 
    { token : string; thumbprint : string } 
    with
        static member FormatTextPlain(x) = x.token + "." + x.thumbprint

let newRegistration (client : IAcmeClient) (email : string) =
    client.NewRegistraton(email)
    |> Async.AwaitTask

let acceptTermsOfService (account : AcmeAccount) =
    account.Data.Agreement <- account.GetTermsOfServiceUri()

let updateRegistration (client : IAcmeClient) account =
    client.UpdateRegistration(account)
    |> Async.AwaitTask
    |> Async.Ignore

let newAuthorization (client : IAcmeClient) hostname =
    client.NewAuthorization(AuthorizationIdentifier(Type = AuthorizationIdentifierTypes.Dns, Value = hostname))
    |> Async.AwaitTask

let httpChallenge (authorization : AcmeResult<Authorization>) =
    authorization.Data.Challenges
    |> Seq.filter (fun x -> x.Type = ChallengeTypes.Http01)
    |> Seq.head
    
let authorizationToken (client : IAcmeClient) challenge =
    let keyAuthorization = client.ComputeKeyAuthorization(challenge)
    match keyAuthorization.Split([|'.'|], 2) with
    | [|token;thumbprint|] ->
        { token = token; thumbprint = thumbprint }
    | _ ->
        failwith "Unexpected keyAuthorization format"

let completeChallenge (client : IAcmeClient) challenge =
    let rec waitForAuthorization location =
        async {
            let! authorization =
                client.GetAuthorization(location)
                |> Async.AwaitTask
            match authorization.Data.Status with
            | EntityStatus.Pending ->
                do! Async.Sleep 10000
                return! waitForAuthorization location
            | _ ->
                return authorization
        }

    async {
        let! completed =
            client.CompleteChallenge(challenge)
            |> Async.AwaitTask
            
        let! authorization =
            waitForAuthorization completed.Location
            
        return authorization
    }

let newCertificate (client : IAcmeClient) hostname certPath =
    async {
        let csr = CertificationRequestBuilder()
        csr.AddName("CN", hostname)
        let! cert =
            client.NewCertificate(csr)
            |> Async.AwaitTask
        let pfx = cert.ToPfx()
        let raw = pfx.Build(hostname, "")
        use file = new FileStream(certPath, FileMode.Create)
        do! file.AsyncWrite(raw)
        return new X509Certificate2(raw)
    }

// exists in certes master, but on in current nuget package
// TODO: replace with certes implementation after package upgrade
module KeyInfo =
    /// Returns DER encoded private key from PEM Private Key Stream
    let from (stream : Stream) =
        use reader = new StreamReader(stream)
        let pemReader = PemReader(reader)
        let keyPair = pemReader.ReadObject() :?> AsymmetricCipherKeyPair
        let privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private)
        privateKey.GetDerEncoded()