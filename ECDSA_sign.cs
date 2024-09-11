using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace TestCrypto;

public class ECDSA_sign
{
    private readonly ECDomainParameters _ecDomainParameters;

    public static byte[] ecdsa_sign(byte[] data, ECPrivateKeyParameters privateKey)
    {
        var signer = new ECDsaSigner();
        signer.Init(true, privateKey);
      
        BigInteger[] signature = signer.GenerateSignature(data);
        
        // Konvertiere die Signatur in ein einzelnes Byte-Array (r und s zusammenfügen)
        var r = signature[0].ToByteArrayUnsigned();
        var s = signature[1].ToByteArrayUnsigned();
        var signatureBytes = new byte[r.Length + s.Length];
        Array.Copy(r, 0, signatureBytes, 0, r.Length);
        Array.Copy(s, 0, signatureBytes, r.Length, s.Length);

        return signatureBytes;  
        
    }
    
    public static byte[] ecdsa_sign(string data, ECPrivateKeyParameters privateKey)
    {
        // String in Byte-Array umwandeln (UTF-8-Kodierung)
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            
        // Die Byte-Array-Überladungsmethode aufrufen
        return ecdsa_sign(dataBytes, privateKey);
    }
    
}