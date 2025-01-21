using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE
{
    public class SignatureGenerator
    {
        public static string SignBlock(string blockId)
        {
            // Convert the block ID to bytes
            byte[] blockBytes = Encoding.UTF8.GetBytes(blockId);

            // Create the signature using the private key
            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(Encryption.RetrieveKeyFromContainer("PRISIGK")), out _);
                byte[] signature = ecdsa.SignData(blockBytes, HashAlgorithmName.SHA256);

                // Return the signature as a Base64-encoded string
                return Convert.ToBase64String(signature);
            }
        }

        public static bool VerifyBlockSignature(string blockId, string base64Signature, string publicSignatureKey)
        {
            // Convert the block ID to bytes
            byte[] blockBytes = Encoding.UTF8.GetBytes(blockId);

            // Decode the Base64-encoded signature
            byte[] signature = Convert.FromBase64String(base64Signature);

            // Verify the signature using the public key
            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicSignatureKey), out _);
                return ecdsa.VerifyData(blockBytes, signature, HashAlgorithmName.SHA256);
            }
        }

        public static string CreateSphereGNCCertificate(string containerName)
        {
            // Open the existing key container
            using var key = CngKey.Open(containerName);

            // Wrap the CngKey as an ECDsa object
            using var ecdsa = new ECDsaCng(key);

            // Use S.P.H.E.R.E as the subject name
            var request = new CertificateRequest(
                new X500DistinguishedName("CN=S.P.H.E.R.E"),
                ecdsa,
                HashAlgorithmName.SHA256
            );


            // Generate a self-signed certificate
            var certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(5));
            byte[] certBytes = certificate.Export(X509ContentType.Cert);
            return Convert.ToBase64String(certBytes);
        }

        public static X509Certificate2 DeserializeCertificateFromString(string base64Cert)
        {
            byte[] certBytes = Convert.FromBase64String(base64Cert);
            return new X509Certificate2(certBytes);
        }
    }
}
