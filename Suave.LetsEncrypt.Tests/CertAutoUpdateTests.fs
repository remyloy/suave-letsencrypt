namespace Suave.LetsEncrypt

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open System.Security.Cryptography.X509Certificates
open System.Threading

[<TestClass>]
type CertAutoUpdateTests () =

    let readCert () =
        new X509Certificate2("Test.pfx")

    [<TestMethod>]
    member this.customWaitForExpiration_Today_IsBefore_Expiration () =
        use cert = readCert ()
        let wait = CertAutoUpdate.customWaitForExpiration (fun () -> DateTime(2018, 5, 24)) TimeSpan.Zero cert
        use cts = new CancellationTokenSource(1000)
        try
           Async.RunSynchronously(wait, cancellationToken = cts.Token)
           Assert.Fail()
        with :? OperationCanceledException -> Assert.IsTrue(true)

    [<TestMethod>]
    member this.customWaitForExpiration_Today_IsAfter_Expiration () =
        use cert = readCert ()
        let wait = CertAutoUpdate.customWaitForExpiration (fun () -> DateTime(2018, 6, 8)) TimeSpan.Zero cert
        use cts = new CancellationTokenSource(1000)
        try
           Async.RunSynchronously(wait, cancellationToken = cts.Token)
           Assert.IsTrue(true)
        with :? OperationCanceledException -> Assert.Fail()

    [<TestMethod>]
    member this.customWaitForExpiration_Today_IsBefore_PaddedExpiration () =
        use cert = readCert ()
        let wait = CertAutoUpdate.customWaitForExpiration (fun () -> DateTime(2018, 5, 21)) (TimeSpan.FromDays 10.0) cert
        use cts = new CancellationTokenSource(1000)
        try
           Async.RunSynchronously(wait, cancellationToken = cts.Token)
           Assert.Fail()
        with :? OperationCanceledException -> Assert.IsTrue(true)

    [<TestMethod>]
    member this.customWaitForExpiration_Today_IsAfter_PaddedExpiration () =
        use cert = readCert ()
        let wait = CertAutoUpdate.customWaitForExpiration (fun () -> DateTime(2018, 6, 1)) (TimeSpan.FromDays 11.0) cert
        use cts = new CancellationTokenSource(1000)
        try
           Async.RunSynchronously(wait, cancellationToken = cts.Token)
           Assert.IsTrue(true)
        with :? OperationCanceledException -> Assert.Fail()
        