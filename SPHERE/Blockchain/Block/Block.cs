using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using System.Web;
using SPHERE;

namespace SPHERE.Blockchain
{
    public enum EncryptionAlgorithm
    {
        AES256,
        RSA2048,
        ECDsa
    }
    public class Block
    {
        public BlockHeader Header { get; set; }                         // Header containing block metadata
        public string EncryptedContact { get; set; }                    // Encrypted contact data object
        public string EncryptedLocalSymmetricKey { get; set; }          // The encrypted key used to encrypt the contact.  can only be decrypted by semi Public Key


        public class BlockHeader
        {
            public string BlockId { get; set; }                             // Unique identifier for the block
            public string PreviousHash { get; set; }                        // Hash of the previous block
            public DateTime BlockCreationTime { get; set; }                 // Creation timestamp
            public DateTime LastUpdateTime { get; set; }                    // Timestap of last Update to the block by validated user.
            public EncryptionAlgorithm EncryptionAlgorithm { get; set; }    // Algorithm used for encryption (e.g. AES256, RSA2048, ECDsa)
            public string? KeyUsagePolicies { get; set; }                   // Policies for key usage
            public string BlockHash { get; set; }                           // Hash of the block for integrity
            public string PublicSignatureKey { get; set; }                  // This is the public key for verifying the signature of commits and the user.
            public string GNCCertificate { get; set; }                      // GNC Container Certificate for the Private Key, Used to validate application used correct security when storing privatekey. 


            // Calculates the hash for the block
            public string CalculateBlockHash()
            {
                string input = $"{BlockId}{PreviousHash}{BlockCreationTime}{EncryptionAlgorithm}{KeyUsagePolicies}";
                using var sha256 = SHA256.Create();
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

            // Creating a Block
            public static Block CreateBlock(string previousHash, string encryptedContactData, EncryptionAlgorithm encryptionAlgorithm)
            {
                DateTime creationTime = DateTime.Now;
                var header = new BlockHeader
                {
                    BlockId = GenerateBlockID(),
                    PreviousHash = previousHash,
                    BlockCreationTime = creationTime,
                    LastUpdateTime = creationTime,
                    EncryptionAlgorithm = encryptionAlgorithm,
                    KeyUsagePolicies = "MESSAGE_ENCRYPTION_ONLY",
                    PublicSignatureKey = Encryption.RetrieveKeyFromContainer("PUBSIGK"),
                    GNCCertificate = Encryption.RetrieveKeyFromContainer("GNCC")
                };

                // Encrypt and store contact data
                string serializedContactData = JsonSerializer.Serialize(encryptedContactData);

                header.BlockHash = header.CalculateBlockHash();


                return new Block
                {
                    Header = header,
                    EncryptedContact = encryptedContactData,
                    EncryptedLocalSymmetricKey = Encryption.RetrieveKeyFromContainer("ELSK"),
                };
            }

            public static string GenerateBlockID()
            {
                byte[] randomBytes = new byte[32]; // 256 bits = 32 bytes
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(randomBytes);
                }
                return Convert.ToBase64String(randomBytes); // Converted to Base64
            }
    }
}



