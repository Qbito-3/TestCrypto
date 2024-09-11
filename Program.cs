namespace TestCrypto
{
    class Program
    {
        static void Main(string[] args)
        {
            //  ECDH_INFO.ecdh_info();

            var curvename = "prime256v1"; // "secp256r1"
            var myKey = ECC_KeyPair.ecc_keypair(curvename);

            string plaintextMessage = "Geheime Nachricht";
            var ciphertext = ECDH_encrypt.ecdh_encrypt(plaintextMessage, myKey.Item2, curvename);

            Console.WriteLine("\nCiphertext: {0}", Convert.ToHexString(ciphertext.Item1));


            string plaintext = ECDH_decrypt.ecdh_decrypt(ciphertext.Item1, ciphertext.Item2);

            Console.WriteLine(plaintext);

            var signature = ECDSA_sign.ecdsa_sign("Geheime Nachricht", myKey.Item1);
            var test = ECDSA_verify.ecdsa_verify("Geheime Nachricht", signature, myKey.Item2);

            Console.WriteLine("\nSignature: {0}", Convert.ToHexString(signature));
            Console.WriteLine("Signature is: {0}", test);
        }
    }
}