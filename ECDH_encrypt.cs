using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;

namespace TestCrypto;
public static class ECDH_encrypt
{
    public static (byte[], byte[], ECPublicKeyParameters) ecdh_encrypt(string plaintextMessage,
        ECPublicKeyParameters? publicKey, string curvename)
    {
        try
        {
           
            var size = 128;
          var myKey =  ECC_KeyPair.ecc_keypair(curvename);
       
           

            var exch = new Org.BouncyCastle.Crypto.Agreement.ECDHBasicAgreement();
            exch.Init(myKey.Item1);
            var sharedSecret = exch.CalculateAgreement(publicKey).ToByteArray();

            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(sharedSecret, null, null));
            byte[] derivedKey = new byte[size / 8];
            hkdf.GenerateBytes(derivedKey, 0, derivedKey.Length);

            // AES-Verschlüsselung
            byte[] ciphertext = EncryptMessage(plaintextMessage, derivedKey);

            return (ciphertext, derivedKey, myKey.Item2);

        }
        catch (Exception e)
        {
            Console.WriteLine("Error: {0}", e.Message);
            return (null, null, null);
        }
    }

    static byte[] EncryptMessage(string plaintext, byte[] key)
        {
            // BouncyCastle AES CBC-Padding Encryption
            var engine = new AesEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher);
            cipher.Init(true, new KeyParameter(key));

            byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            byte[] encryptedBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];
            int length = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, encryptedBytes, 0);
            cipher.DoFinal(encryptedBytes, length);

            return encryptedBytes;
        
    }
    
}