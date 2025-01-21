using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace SPHERE
{ 
    public class KeyGenerator
    {


        public static void GeneratePersonalKeyPairSets()
        {
            using var signaturePair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var commPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var privateSignatureKey = signaturePair.ExportPkcs8PrivateKey();
            var publicSignatureKey = signaturePair.ExportSubjectPublicKeyInfo();
            var privateCommunicationKey = commPair.ExportPkcs8PrivateKey();
            var publicCommunicationKey = commPair.ExportSubjectPublicKeyInfo();

            try
            {
                string publicSignatureKeyBase64 = Convert.ToBase64String(publicSignatureKey);
                string privateSignatureKeyBase64 = Convert.ToBase64String(privateSignatureKey);
                string publicCommunicationKeyBase64 = Convert.ToBase64String(publicCommunicationKey);
                string privateCommunicationKeyBase64 = Convert.ToBase64String(privateCommunicationKey);

                Encryption.StoreKeyInContainer(privateSignatureKeyBase64, "PRISGNK");
                Encryption.StoreKeyInContainer(publicSignatureKeyBase64, "PUBSGNK");
                Encryption.StoreKeyInContainer(privateCommunicationKeyBase64, "PRICOMK");
                Encryption.StoreKeyInContainer(publicCommunicationKeyBase64, "PUBCOMK");

                privateSignatureKeyBase64 = null;
                publicSignatureKeyBase64 = null;
                publicCommunicationKeyBase64 = null;
                privateCommunicationKeyBase64 = null;
            }
            finally
            {

                ClearSensitiveData(privateSignatureKey);
                ClearSensitiveData(publicSignatureKey);
                ClearSensitiveData(privateCommunicationKey);
                ClearSensitiveData(publicCommunicationKey);

                privateSignatureKey = null;
                publicSignatureKey = null;
                publicCommunicationKey = null;
                privateCommunicationKey = null;
            }

        }

        public static void GenerateNodeKeyPair()
        {

            using var nodeePair = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var privateKey = nodeePair.ExportPkcs8PrivateKey();
            var publicKey = nodeePair.ExportSubjectPublicKeyInfo();

            try
            {
                string publicKeyBase64 = Convert.ToBase64String(publicKey);
                string privateeKeyBase64 = Convert.ToBase64String(privateKey);

                Encryption.StoreKeyInContainer(privateeKeyBase64, "PRINODK");
                Encryption.StoreKeyInContainer(publicKeyBase64, "PUBNODK");

                privateeKeyBase64 = null;
                publicKeyBase64 = null;
            }
            finally
            {

                ClearSensitiveData(privateKey);
                ClearSensitiveData(publicKey);
                privateKey = null;
                publicKey = null;
            }
        }


        public static string CreateVerificationKey(string privateKey, string salt)
        {
            // Create the verification key (VK) from the private key
            using var hkdf = new HMACSHA256(Convert.FromBase64String(privateKey));
            byte[] verificationKey = hkdf.ComputeHash(Encoding.UTF8.GetBytes(salt));
            return Convert.ToBase64String(verificationKey);
        }

        public static string GenerateSymmetricKey()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            return Convert.ToBase64String(ecdh.DeriveKeyMaterial(ecdh.PublicKey));
        }

        public static void ClearSensitiveData(byte[] data)
        {
            if (data != null)
            {
                Array.Clear(data, 0, data.Length); // Overwrite with zeroes
            }
        }
    }
}
