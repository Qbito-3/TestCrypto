using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace TestCrypto
{
    public static class ECDSA_verify
    {
        public static bool ecdsa_verify(byte[] data, byte[] signature, ECPublicKeyParameters publicKey)
        {
            var signer = new ECDsaSigner();
            signer.Init(false, publicKey);
            
            // Extrahiere r und s aus dem Signatur-Byte-Array
            int len = signature.Length / 2;
            var r = new BigInteger(1, signature, 0, len);
            var s = new BigInteger(1, signature, len, len);

            // Überprüfe die Signatur
            return signer.VerifySignature(data, r, s);
        }

        // Überladene Methode für String-Eingaben
        public static bool ecdsa_verify(string data, byte[] signature, ECPublicKeyParameters publicKey)
        {
            // String in Byte-Array umwandeln (UTF-8-Kodierung)
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            
            // Die Byte-Array-Überladungsmethode aufrufen
            return ecdsa_verify(dataBytes, signature, publicKey);
        }
    }
}