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
using SPHERE.Configure;

namespace SPHERE.Blockchain
{
    public enum EncryptionAlgorithm
    {
        AES256,
        RSA2048,
        ECDsa
    }

    /// <summary>
    /// The Block exists to store the encrypted contact in a decenterilized manner. 
    /// 
    /// Block editing. 
    /// Blocks are signed with the Private Signature Key. This key is attached to the user that created the block.  Block edits that are recievd by a node, can have attached signatures. 
    /// if the signature is valid the node will accept the edit and update the node or pass on the request, updating it to be verified by the node. 
    /// (Request could not be addded to verified by so much of the network and keep bouncing till that point and then updates will happen)
    /// The block edit request would be just the signature for approval and the already encryptedcontact, to which the old contact block is replaced as a while.  
    /// 
    ///
    /// </summary>
    public class Block
    {
        public BlockHeader Header { get; set; }                         // Header containing block metadata
        public string EncryptedContact { get; set; }                    // Encrypted contact data object
        public string EncryptedLocalSymmetricKey { get; set; }          // The encrypted key used to encrypt the contact.  can only be decrypted by semi Public Key


        public class BlockHeader
        {
            public string BlockId { get; set; }                             // Unique identifier for the block
            public string BlockVersion {  get; set; }                       // Block Versions allow for deserialvation of different blocks as the platform evolves.
            public string ContactVersion { get; set; }                      // Contact versions would allow for deserialation of different contact styles as the platform evolves must be on the contact and the block.
            public DateTime BlockCreationTime { get; set; }                 // Creation timestamp
            public DateTime LastUpdateTime { get; set; }                    // Timestap of last Update to the block by validated user.
            public EncryptionAlgorithm EncryptionAlgorithm { get; set; }    // Algorithm used for encryption (e.g. AES256, RSA2048, ECDsa)
            public string? KeyUsagePolicies { get; set; }                   // Policies for key usage
            public string BlockHash { get; set; }                           // Hash of the block for integrity
            public string PublicSignatureKey { get; set; }                  // This is the public key for verifying the signature of commits and the user.
            public string GNCCertificate { get; set; }                      // GNC Container Certificate for the Private Key, Used to validate application used correct security when storing privatekey. 
            public string PreviousHash { get; set; }                        // Hash of the previous block

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
                    PublicSignatureKey = ServiceAccountManager.RetrieveKeyFromContainer("PUBSIGK"),
                    GNCCertificate = ServiceAccountManager.RetrieveKeyFromContainer("GNCC")
                };

                // Encrypt and store contact data
                string serializedContactData = JsonSerializer.Serialize(encryptedContactData);

                header.BlockHash = header.CalculateBlockHash();


                return new Block
                {
                    Header = header,
                    EncryptedContact = encryptedContactData,
                    EncryptedLocalSymmetricKey = ServiceAccountManager.RetrieveKeyFromContainer("ELSK"),
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



