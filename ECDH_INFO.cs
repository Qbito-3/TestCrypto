using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;

namespace TestCrypto
{
  public static class ECDH_INFO
    {
        public static void ecdh_info()
        {
            try
            {
                var curvename = "prime256v1";
                var size = 128;
           //     if (args.Length > 0) curvename = args[0];
      //          if (args.Length > 1) size = Convert.ToInt32(args[1]);

                X9ECParameters ecParams = ECNamedCurveTable.GetByName(curvename);
                var n = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());

                ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(n, new SecureRandom());

                ECKeyPairGenerator generator = new ECKeyPairGenerator();
                generator.Init(keygenParams);

                var keyPair = generator.GenerateKeyPair();
                var BobprivateKey = (ECPrivateKeyParameters)keyPair.Private;
                var BobpublicKey = (ECPublicKeyParameters)keyPair.Public;

                keyPair = generator.GenerateKeyPair();
                var AliceprivateKey = (ECPrivateKeyParameters)keyPair.Private;
                var AlicepublicKey = (ECPublicKeyParameters)keyPair.Public;

                var exch = new Org.BouncyCastle.Crypto.Agreement.ECDHBasicAgreement();
                exch.Init(AliceprivateKey);
                var secretAlice = exch.CalculateAgreement(BobpublicKey).ToByteArray();

                exch = new Org.BouncyCastle.Crypto.Agreement.ECDHBasicAgreement();
                exch.Init(BobprivateKey);
                var secretBob = exch.CalculateAgreement(AlicepublicKey).ToByteArray();

                // Use HKDF to derive final key - ignore salt and extra info
                var hkdf = new HkdfBytesGenerator(new Sha256Digest());
                hkdf.Init(new HkdfParameters(secretAlice, null, null));
                byte[] derivedKey = new byte[size / 8];
                hkdf.GenerateBytes(derivedKey, 0, derivedKey.Length);

                Console.WriteLine("\nDerived Key (using secret and HKDF):\t{0}", Convert.ToHexString(derivedKey));

                Console.WriteLine("\n=== Static keys ===");
                Console.WriteLine("Bob Private key {0}", BobprivateKey.D);
                Console.WriteLine("Bob Public key {0}, {1}", BobpublicKey.Q.AffineXCoord, BobpublicKey.Q.AffineYCoord);
                Console.WriteLine("\nAlice Private key {0}", AliceprivateKey.D);
                Console.WriteLine("Alice Public key {0}, {1}", AlicepublicKey.Q.AffineXCoord, AlicepublicKey.Q.AffineYCoord);
                Console.WriteLine("\nShared Secret:\t{0}", Convert.ToHexString(secretAlice));

                Console.WriteLine("\n=== elliptischen Kurven Parameter ===\n");
                Console.WriteLine("Type: {0}", curvename);
                Console.WriteLine("\nG={0},{1}", ecParams.G.AffineXCoord, ecParams.G.AffineYCoord);
                Console.WriteLine("G ist ein festgelegter Punkt auf der elliptischen Kurve, der als Startpunkt für die Schlüsselgenerierung verwendet wird. Der Generatorpunkt wird auch als Basispunkt bezeichnet.\n Dieser Punkt wird verwendet, um andere Punkte auf der Kurve durch wiederholte Addition zu berechnen. Er ist entscheidend für die Berechnung von Schlüsseln in kryptographischen Verfahren wie ECDSA und ECDH.\n");
                Console.WriteLine("N (order)={0}", ecParams.N);
                Console.WriteLine("N ist die Ordnung des Generatorpunkts G. Das bedeutet, wenn man den Generatorpunkt G wiederholt zu sich selbst addiert (skalare Multiplikation),\n erhält man nach N Additionen den Punkt am Unendlichen (das neutrale Element der elliptischen Kurve). Die Ordnung gibt also an, wie viele verschiedene Punkte man durch die Multiplikation des Generatorpunkts mit verschiedenen Skalaren erhalten kann, bevor man wieder beim Ausgangspunkt landet.\n");
                Console.WriteLine("H ={0}", ecParams.H);
                Console.WriteLine("H ist der Cofaktor der Kurve. Er ist definiert als das Verhältnis zwischen der Gesamtzahl der Punkte auf der Kurve und der Ordnung N des Generatorpunkts:\nH = (Gesamtanzahl der Punkte auf der Kurve)/N  \nIn vielen kryptographischen Kurven ist der Cofaktor H gleich 1, was bedeutet, dass alle Punkte auf der Kurve direkt durch Multiplikation des Generatorpunkts G erreicht werden können.\n");
                Console.WriteLine("A ={0}\nB={1}", ecParams.Curve.A, ecParams.Curve.B);
                Console.WriteLine("A und B sind die Konstanten, die die Form der elliptischen Kurve definieren. Für eine elliptische Kurve in der Weierstraß-Form gilt die Gleichung:\ny^2 = x^3 + Ax + B  \nHier bestimmen A und B die Struktur der Kurve. Unterschiedliche Werte von A und B führen zu unterschiedlichen Kurven, die jeweils spezifische kryptographische Eigenschaften haben.\n");
                Console.WriteLine("Field size={0}", ecParams.Curve.FieldSize);

                // Beispielnachricht
                string plaintextMessage = "Geheime Nachricht";

                // AES-Verschlüsselung
                byte[] ciphertext = EncryptMessage(derivedKey, plaintextMessage);

                Console.WriteLine("\nCiphertext: {0}", Convert.ToHexString(ciphertext));

                // Optional: Entschlüsseln zum Testen
                string decryptedMessage = DecryptMessage(derivedKey, ciphertext);
                Console.WriteLine("Decrypted Message: {0}", decryptedMessage);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        public static byte[] EncryptMessage(byte[] key, string plaintext)
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

        public static string DecryptMessage(byte[] key, byte[] ciphertext)
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
}
