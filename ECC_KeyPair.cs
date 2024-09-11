using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;


namespace TestCrypto;

public static class ECC_KeyPair
{
    public static (ECPrivateKeyParameters, ECPublicKeyParameters) ecc_keypair(string curvename)
    {
        try
        {


            X9ECParameters ecParams = ECNamedCurveTable.GetByName(curvename);
            var n = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());

            ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(n, new SecureRandom());

            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(keygenParams);

            var keyPair = generator.GenerateKeyPair();
            var privateKey = (ECPrivateKeyParameters)keyPair.Private;
            var publicKey = (ECPublicKeyParameters)keyPair.Public;
            return (privateKey, publicKey);

        }
        catch (Exception e)
        {
            Console.WriteLine("Error: {0}", e.Message);
            return (null, null);
        }
    }
}