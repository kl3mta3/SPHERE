using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SPHERE.Blockchain;
using SPHERE.Security;
using static SPHERE.Configure.TokenManager;

namespace SPHERE.Configure
{

    /// <summary>
    /// 
    /// Standard Signature Generation 
    /// 
    /// We sign the blocks with the Private Signature Key to validate them as the owner later. 
    /// 
    /// We sign Nodes with the Private Node Signature Key to Verify we created packets we send. 
    /// 
    /// To ensure that all nodes are using the correct methods of storing the keys in CNG Containers.  
    /// We do this by requesting a Block have a valid CNG Container Signature for the primary Private Signature Key.
    /// 
    /// ### We do acknowledge that this is a limiter on the platforms that can host a node and Might be changed. 
    /// ### It just crucial to ensure all developers that might try to build and access the chain on other 
    /// ### platforms are forced to adhere to the same standards of data security. 
    /// 
    /// 
    /// </summary>
    public class SignatureGenerator
    {
        public static string CreateBlockSignature(string blockId)
        {

            bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";
            if (isTesting)
            {
                // Convert the block ID to bytes
                byte[] blockBytes = Encoding.UTF8.GetBytes(blockId);

                // Create the signature using the private key
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeSignatureKey), out _);
                    byte[] signature = ecdsa.SignData(blockBytes, HashAlgorithmName.SHA256);

                    // Return the signature as a Base64-encoded string
                    return Convert.ToBase64String(signature);
                }
            }
            else
            {
                // Convert the block ID to bytes
                byte[] blockBytes = Encoding.UTF8.GetBytes(blockId);

                // Create the signature using the private key
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivatePersonalSignatureKey), out _);
                    byte[] signature = ecdsa.SignData(blockBytes, HashAlgorithmName.SHA256);

                    // Return the signature as a Base64-encoded string
                    return Convert.ToBase64String(signature);
                }

            }
        }

        public static string CreateNodeSignature(string nodeId)
        {

            bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";
            if (isTesting)
            {
                // Convert the block ID to bytes
                byte[] blockBytes = Encoding.UTF8.GetBytes(nodeId);

                // Create the signature using the private key
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeSignatureKey), out _);
                    byte[] signature = ecdsa.SignData(blockBytes, HashAlgorithmName.SHA256);

                    // Return the signature as a Base64-encoded string
                    return Convert.ToBase64String(signature);
                }
            }
            else
            {
                // Convert the block ID to bytes
                byte[] blockBytes = Encoding.UTF8.GetBytes(nodeId);

                // Create the signature using the private key
                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateNodeSignatureKey), out _);
                    byte[] signature = ecdsa.SignData(blockBytes, HashAlgorithmName.SHA256);

                    // Return the signature as a Base64-encoded string
                    return Convert.ToBase64String(signature);
                }


            }
        }

        // Sign a byte array using the private key
        public static byte[] SignByteArray(byte[] data)

        {

            bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";
            if (isTesting)
            {
                // Create the signature using the private key
                try
                {
                    using (var ecdsa = ECDsa.Create())
                    {
                        byte[] hash = SHA256.HashData(data);
                        ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeSignatureKey), out _);
                        byte[] signature = ecdsa.SignData(hash, HashAlgorithmName.SHA256);

                        // Return the signature as a Base64-encoded string
                        return signature;

                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return null;
                }
            }
            else
            {
                // Create the signature using the private key
                try
                {
                    using (var ecdsa = ECDsa.Create())
                    {
                        byte[] hash = SHA256.HashData(data);
                        ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateNodeSignatureKey), out _);
                        byte[] signature = ecdsa.SignHash(hash);

                    // Return the signature as a Base64-encoded string
                    return signature;

                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return null;
                }


            }
        }

        // Verify a byte array using the public key
        public static bool VerifyByteArray(byte[] data, byte[] signature, byte[] publicKey)
        {
            try
            {
                // Convert the Base64 public key back to a byte array
                byte[] publicKeyBytes = publicKey;

                // Import the public key
                using (ECDsa ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                    // Convert the signature back to a byte array
                    byte[] signatureBytes = signature;
                    byte[] receivedHash = SHA256.HashData(data);

                    // Verify the signature
                    return ecdsa.VerifyHash(receivedHash, signatureBytes);
                }
            }
            catch (Exception ex)
            {
                // Log or handle exceptions (optional)
                Console.WriteLine($"Error verifying signature: {ex.Message}");
                return false;
            }
        }

        // Sign a PushTokens using the private key
        public static string SignPushToken(PushToken token)
        {

            bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";
            if (isTesting)
            {
                string data = $"{token.IssuerId}|{token.ReceiverId}|{token.Timestamp:o}";

                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeSignatureKey), out _);
                    byte[] signatureBytes = ecdsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256);
                    return Convert.ToBase64String(signatureBytes);
                }
            }
            else
            {
                string data = $"{token.IssuerId}|{token.ReceiverId}|{token.Timestamp:o}";

                using (var ecdsa = ECDsa.Create())
                {
                    ecdsa.ImportPkcs8PrivateKey(ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateNodeSignatureKey), out _);
                    byte[] signatureBytes = ecdsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256);
                    return Convert.ToBase64String(signatureBytes);
                }


            }
        }

        // Verify a received PushToken using the public key
        public static bool VerifyReceivedPushToken(Node node, PushToken token, byte[] publicKey)
        {
            if (node.Peer.NodeId == token.ReceiverId || node.Peer.NodeId != token.IssuerId)
            {
                return false;
            }

            string data = $"{token.IssuerId}|{token.ReceiverId}|{token.Timestamp:o}";

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                byte[] signatureBytes = Convert.FromBase64String(token.Signature);
                return ecdsa.VerifyData(Encoding.UTF8.GetBytes(data), signatureBytes, HashAlgorithmName.SHA256);
            }
        }

        // Verify an Issued PushToken using the public key
        public static bool VerifyIssuedPushToken(Node node, PushToken token, byte[] publicKey)
        {
            if (node.Peer.NodeId != token.ReceiverId || node.Peer.NodeId == token.IssuerId)
            {
                return false;
            }

            string data = $"{token.IssuerId}|{token.ReceiverId}|{token.Timestamp:o}";

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                byte[] signatureBytes = Convert.FromBase64String(token.Signature);
                return ecdsa.VerifyData(Encoding.UTF8.GetBytes(data), signatureBytes, HashAlgorithmName.SHA256);
            }
        }


        public static bool VerifyBlockSignature(string blockId, string base64Signature, byte[] publicSignatureKey)
        {
            // Convert the block ID to bytes
            byte[] blockBytes = Encoding.UTF8.GetBytes(blockId);

            // Decode the Base64-encoded signature
            byte[] signature = Convert.FromBase64String(base64Signature);

            // Verify the signature using the public key
            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(publicSignatureKey, out _);
                return ecdsa.VerifyData(blockBytes, signature, HashAlgorithmName.SHA256);
            }
        }

        public static byte[] CreateSphereCNGCertificate(KeyGenerator.KeyType keyType)
        {
            string containerName=keyType.ToString();
            try
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
                return certBytes;
            }
            catch (Exception ex)
            {
            }
            throw new Exception("Failed to Generate CNG Certificate.");
        }

        public static X509Certificate2 DeserializeCertificateFromString(string base64Cert)
        {
            byte[] certBytes = Convert.FromBase64String(base64Cert);
            return new X509Certificate2(certBytes);
        }
    }
}
