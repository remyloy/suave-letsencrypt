open Suave
open Suave.LetsEncrypt
open System
open System.Net
open System.Threading

let helloWorld () =
    startWebServer defaultConfig (Successful.OK "Hello World")

let customHelloWorld cert cancellationToken =
    use cts = CancellationTokenSource.CreateLinkedTokenSource(Async.DefaultCancellationToken, cancellationToken)
    let config = 
        { defaultConfig with 
            bindings = [ HttpBinding.create (HTTPS cert) IPAddress.Any 443us ]
            cancellationToken = cts.Token }
    let app = 
        Successful.OK "Hello World with cert"
    startWebServer config app

[<EntryPoint>]
let main argv =

    let runServerWith =
        CertAutoUpdate.lift customHelloWorld

    let config =
        CertAutoUpdate.createConfig "mail@example.com" "example.com"
    
    printfn "Starting Cert Auto Update"

    let task = 
        Async.StartAsTask (CertAutoUpdate.startWebServerAsync config runServerWith, cancellationToken = CancellationToken.None)

    printfn "Press any key to stop suave server."
    Console.ReadKey(true) |> ignore
    printfn "Cancelling suave server."
    Async.CancelDefaultToken()
    printfn "Cert Auto Update Result: %A" task.Result
    0
