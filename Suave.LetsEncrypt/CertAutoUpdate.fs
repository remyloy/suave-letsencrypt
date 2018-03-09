namespace Suave.LetsEncrypt

open System
open System.IO
open System.Net
open System.Threading
open Acme

/// Contains all necessary information to setup the auto update mechanism
type Configuration = 
    {
    /// A path to a file which will contain the account information.
    /// Keep that file save as it contains the private key for your Lets Encrypt account.
    filePath: string
    /// Contact email associated with this account. Is only relevant before the account is created.
    /// That means changes to this value won't have any effect afterwards.
    email: string
    /// Hostname to get certificates for. Is only relevant before the host is authorized.
    /// That means changes to this value won't have any effect afterwards.
    hostname: string
    /// Sets how many days in advance of the certs expiration date a new cert is aquired
    padding: TimeSpan
    /// The directory path for where the downloaded cert files should be stored.
    /// E.g. /etc/suave-letsencrypt, or any path which is not accesible to others.
    certPath : string
    /// Allows you to provide your own clock
    today : unit -> DateTime
    }

type CertAutoUpdateResult =
    | Stopped
    | Failed of string

type Msg =
    | ServerStopped
    | ServerCancelled
    | WaitedForCertExpiration

type StartServer = System.Security.Cryptography.X509Certificates.X509Certificate2 -> CancellationToken -> unit

/// A module for automating the process of acquiring a certificate from Lets Encrypt
/// and keeping that certificate valid.
/// The only way to inject the certificate into Suave is via the initial HTTPS binding
/// configuration. As I don't see a method which can update the server without redefining
/// the HTTPS binding, I have choosen a callback based approach to integrate with Suave.
/// That decision turned the whole module and the way it is consumption more like into
/// a framework instead of library.
/// All private keys (for the account and ther cert itself) are not password encoded,
/// so use a safe place to store them. Adjust the configuration accordingly.
module CertAutoUpdate =

    type internal Certificate=
        | NotRequested
        | Available of System.Security.Cryptography.X509Certificates.X509Certificate2

    type internal RegisteredData = 
        { config: Configuration
        ; account : Account
        ; authorizationExpiration : DateTimeOffset
        ; cert: Certificate 
        }

    type internal Registration
        = Unregistered of Configuration
        | Registered of RegisteredData
    
    /// Creates a configuration
    let createConfig email hostname =
        { filePath = "account.zip"
        ; email = sprintf "mailto:%s" email
        ; hostname = hostname
        ; padding = TimeSpan.FromDays 7.0
        ; certPath = ""
        ; today = fun () -> DateTime.Now
        } 

    let internal init (config : Configuration)   =

        let setupDirectories data certs =
            let fileDir = Path.GetDirectoryName(data)
            ignore <| Directory.CreateDirectory(fileDir)
            let certDir = certs
            ignore <| Directory.CreateDirectory(certDir)

        let readCert config =
            let certFileName = sprintf "%s.pfx" config.hostname
            let certFilePath = Path.Combine(config.certPath, certFileName)
            if File.Exists certFilePath then
                new System.Security.Cryptography.X509Certificates.X509Certificate2(certFilePath)
                |> Ok
            else
                Error "cert file does not exist"

        let evaluateCertExpiration config (cert : System.Security.Cryptography.X509Certificates.X509Certificate2) = 
            if config.today() < cert.NotAfter.Add(-config.padding) then
                Ok cert
            else
                Error "cert is expired or will expire soon"
        
        setupDirectories config.filePath config.certPath
        if File.Exists config.filePath then
            let (account, expirationDate) = Account.Load config.filePath
            let cert =
                readCert config
                |> Result.bind (evaluateCertExpiration config)
                |> function
                | Ok cert -> Available cert
                | Error msg -> NotRequested

            Registered { config = config; account = account; authorizationExpiration = expirationDate; cert = cert }
        else
            Unregistered config

    let private anonAcmeClient () =
        new Certes.AcmeClient(Certes.Acme.WellKnownServers.LetsEncrypt)

    let private acmeClient (account : Account) =
        let client = anonAcmeClient ()
        client.Use(Certes.Pkcs.KeyInfo(PrivateKeyInfo = account.key))
        client

    let private hostFile path content cancellationToken =
        async {
            let serverConfig =
                { Suave.Web.defaultConfig with 
                    bindings = [ Suave.Http.HttpBinding.create Suave.Http.HTTP IPAddress.Any 80us ]
                    cancellationToken = cancellationToken }
            let app =
                let content =
                    Suave.WebPart.compose (Suave.Writers.setMimeType "text/plain") (Suave.Successful.OK content)
                Suave.WebPart.compose (Suave.Filters.path path) content

            let (ready, server) = Suave.Web.startWebServerAsync serverConfig app
            Async.Start(server, cancellationToken)
            let! _ = ready
            return ()
        }
    
    let authorizeHost (config : Configuration) account =
        async {
            use client = acmeClient account

            let! authorization = Acme.newAuthorization client config.hostname
            let challenge = Acme.httpChallenge authorization
            let keyAuthorization = Acme.authorizationToken client challenge

            use cts = new CancellationTokenSource()
            let challengePath = sprintf "/.well-known/acme-challenge/%s" keyAuthorization.token        
            let challengeContent = Acme.KeyAuthorization.FormatTextPlain keyAuthorization
            do! hostFile challengePath challengeContent cts.Token
            let! completedAuthorization = Acme.completeChallenge client challenge
            cts.Cancel()

            if completedAuthorization.Data.Status = Certes.Acme.EntityStatus.Valid then
                return Ok completedAuthorization.Data.Expires
            else
                return Error completedAuthorization.Data.Status
        }

    let internal register config =
        async {
            use client = anonAcmeClient()
            let! account = Acme.newRegistration client config.email
            Acme.acceptTermsOfService account
            do! Acme.updateRegistration client account

            let acc = { key = account.Key.PrivateKeyInfo; location = account.Location.AbsoluteUri }
            let! authorizationResult = authorizeHost config acc
            match authorizationResult with
            | Ok expirationDate ->
                Account.Save acc expirationDate config.filePath 
                let data = { config = config; account = acc; authorizationExpiration = expirationDate; cert = NotRequested } 
                return data |> Ok
            | Error err ->
                return Error err
        }

    let internal requestCert (config : Configuration) account =
        async {
            use client = acmeClient account
            let certFileName = sprintf "%s.pfx" config.hostname
            let certFilePath = Path.Combine(config.certPath, certFileName)
            let! cert = Acme.newCertificate client config.hostname certFilePath
            return cert |> Available
        }
    
    let private sleep (timespan : TimeSpan) =
        timespan.TotalMilliseconds 
        |> int 
        |> Async.Sleep

    /// Creates an async workflow which returns when the cert is about to expire.
    let customWaitForExpiration getNow padding (cert : System.Security.Cryptography.X509Certificates.X509Certificate2)  =
        async {
            let! cancellationToken = Async.CancellationToken
            let oneDay = TimeSpan.FromDays(1.0)
            let paddedNotAfter = cert.NotAfter.Add(-padding)
            while getNow() < paddedNotAfter && (not cancellationToken.IsCancellationRequested) do
                do! sleep oneDay
        }
    
    /// Can be used to lift a default run-suave-function to provide the
    /// expected behavior for consumption by the CertAutoUpdate module.
    let lift (f : StartServer) =
        fun cert cancellationToken ->
            async {
                try
                    f cert cancellationToken
                    return Some Msg.ServerStopped
                with :? OperationCanceledException -> 
                    return Some Msg.ServerCancelled
            }

    let startWebServerAsync config callback = 

        let waitCertExpiration cert = 
            async {
                do! customWaitForExpiration config.today config.padding cert 
                return Some WaitedForCertExpiration
            }

        let rec registered data =
            async {
                match data.cert with
                | NotRequested ->
                    let! cert = requestCert data.config data.account
                    return! registered { data with cert = cert}
                | Available cert ->
                    use cts = new CancellationTokenSource()
                    let server = callback cert cts.Token
                    let! whatHappended = Async.Choice [server; waitCertExpiration cert]
                    match whatHappended with
                    | Some msg ->
                        match msg with
                        | WaitedForCertExpiration ->
                            cts.Cancel()
                            do! server |> Async.Ignore
                            return! registered { data with cert = NotRequested }
                        | ServerStopped -> return Stopped
                        | ServerCancelled -> return Stopped
                    | None ->
                        return Failed "Unexpected state: Neither server stopped nor cert was going to expire."
            }
        and unregistered config =
            async {
                let! result = register config
                match result with
                | Ok registration ->
                    return! registered registration
                | Result.Error msg ->
                    return Failed msg
            }
        and loop state =
            async {
                match state with
                | Unregistered config ->
                    return! unregistered config
                | Registered data ->
                    return! registered data
            }

        let state = 
            init config
        loop state

    let startWebServer config callback =
        startWebServerAsync config callback 
        |> Async.RunSynchronously