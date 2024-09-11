using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;

namespace TestCrypto;

public class ECDH_decrypt
{
    public static string ecdh_decrypt(byte[] ciphertext,
        byte[] derivedKey)
    {
        try
        {
            //   Entschlüsseln zum Testen
            string decryptedMessage = DecryptMessage(ciphertext, derivedKey);

            return decryptedMessage;
        }
        catch (Exception e)
        {
            Console.WriteLine("Error: {0}", e.Message);
        }

        return "";
    }

    private static string DecryptMessage(byte[] ciphertext, byte[] key)
    {
        // BouncyCastle AES CBC-Padding Decryption
        var engine = new AesEngine();
        var blockCipher = new CbcBlockCipher(engine);
        var cipher = new PaddedBufferedBlockCipher(blockCipher);
        cipher.Init(false, new KeyParameter(key));

        byte[] decryptedBytes = new byte[cipher.GetOutputSize(ciphertext.Length)];
        int length = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, decryptedBytes, 0);
        cipher.DoFinal(decryptedBytes, length);

        return System.Text.Encoding.UTF8.GetString(decryptedBytes).TrimEnd('\0');
    }
}