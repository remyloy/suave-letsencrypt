namespace Suave.LetsEncrypt

open System
open System.IO
open System.IO.Compression
open Org.BouncyCastle.Asn1.Sec
open Org.BouncyCastle.Crypto
open Org.BouncyCastle.Crypto.Parameters
open Org.BouncyCastle.OpenSsl
open Org.BouncyCastle.Pkcs
open Org.BouncyCastle.Security

type Account = { key : byte array; location : string }
    with
    static member Save (acc : Account) (expirationDate : DateTimeOffset) filePath =
        let parseKey (keyParam : AsymmetricKeyParameter) =
            match keyParam with
            | :? RsaPrivateCrtKeyParameters as privateKey ->
                let publicKey = RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent)
                AsymmetricCipherKeyPair(publicKey, privateKey)
            | :? ECPrivateKeyParameters as privateKey ->
                let domain = privateKey.Parameters
                let q = domain.G.Multiply(privateKey.D)
                let curveId =
                    match domain.Curve.FieldSize with
                    | 256 ->
                        SecObjectIdentifiers.SecP256r1
                    | 384 ->
                        SecObjectIdentifiers.SecP384r1
                    | 521 ->
                        SecObjectIdentifiers.SecP521r1
                    | _ ->
                        failwith "Not supported"
                let publicKey = ECPublicKeyParameters("EC", q, curveId)
                AsymmetricCipherKeyPair(publicKey, privateKey)
            | _ ->
                failwith "Not supported"

        let writeKey (key : byte array) (zip : ZipArchive) =
            let entry = zip.CreateEntry("private.pem")
            use streamWriter = new StreamWriter(entry.Open())

            let keyParam = PrivateKeyFactory.CreateKey(key)
            let keyPair = parseKey(keyParam)

            let pemWriter = PemWriter(streamWriter)
            pemWriter.WriteObject(keyPair)

        let writeLocation (location : string) (zip : ZipArchive) =
            let entry = zip.CreateEntry("location.txt")
            use streamWriter = new StreamWriter(entry.Open())
            streamWriter.WriteLine(location)            

        let expirationDate (zip : ZipArchive) =
            let entry = zip.CreateEntry("expirationDate.txt")
            use streamWriter = new StreamWriter(entry.Open())
            streamWriter.WriteLine(expirationDate.ToString("o"))            

        use file = File.Create(filePath)       
        use zip = new ZipArchive(file, ZipArchiveMode.Create)
        writeKey acc.key zip
        writeLocation acc.location zip
        expirationDate zip
        
    static member Load filePath =
        let readKey (zip : ZipArchive) =
            let entry = zip.GetEntry("private.pem")
            use streamReader = new StreamReader(entry.Open())
            let pemReader = PemReader(streamReader)
            let keyPair = pemReader.ReadObject() :?> AsymmetricCipherKeyPair                
            PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private).GetDerEncoded()

        let readLocation (zip : ZipArchive) =
            let entry = zip.GetEntry("location.txt")
            use streamReader = new StreamReader(entry.Open())
            streamReader.ReadToEnd() 

        let readExpirationDate (zip : ZipArchive) =
            let entry = zip.GetEntry("expirationDate.txt")
            use streamReader = new StreamReader(entry.Open())
            streamReader.ReadToEnd() 
            |> DateTimeOffset.Parse

        use file = File.Open(filePath, FileMode.Open)
        use zip = new ZipArchive(file, ZipArchiveMode.Read)
        let key = readKey zip
        let location = readLocation zip
        let expirationDate = readExpirationDate zip
        { key = key; location = location }, expirationDate

