using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SPHERE.Configure;
using SPHERE.Configure.Logging;
using SPHERE.Security;
using static SPHERE.PacketLib.Packet.PacketBuilder;
using static SPHERE.PacketLib.Packet;


namespace SPHERE.Blockchain
{
    public enum EncryptionAlgorithm
    {
        AES256,
        RSA2048,
        SHA256,
        ECDsa
    }

    /// <summary>
    /// The Block exists to store the encrypted contact in a decentralized manner. 
    /// 
    /// Block editing. 
    /// Blocks are signed with the Private Signature Key. This key is attached to the user that created the block.  Block edits that are received by a node, can have attached signatures. 
    /// if the signature is valid the node will accept the edit and update the node or pass on the request, updating it to be verified by the node. 
    /// (Request could not be added to verified by so much of the network and keep bouncing till that point and then updates will happen)
    /// The block edit request would be just the signature for approval and the already encrypted contact, to which the old contact block is replaced as a while.  
    /// 
    /// To create a block Contact the first time Private Keys are needed to be generated so a Password is needed to be made with either Password.CreatePasswordWithString(string password) or Password.GenerateRandomPassword(int length) defaults to 16 characters.
    ///
    ///
    /// </summary>
    public class Block
    {
        public enum BlockType
        {
            Contact,
            Reputation,
            Transaction,
        }

        [JsonPropertyName("Header")]
        public required BlockHeader Header { get; set; }                         // Header containing block meta data

        [JsonPropertyName("EncryptedContact")]
        public string? EncryptedContact { get; set; }                   // Encrypted contact data (only for Contact Blocks)

        [JsonPropertyName("ReputationBlock")]
        public string? ReputationBlock { get; set; }                    // Encrypted reputation data (only for Reputation Blocks)

        [JsonPropertyName("encryptedTransaction")]
        public string? TransactionBlock { get; set; }                // Encrypted transaction data (only for Transaction Blocks)

        [JsonPropertyName("encryptedLocalSymmetricKey")]
        public required byte[] EncryptedLocalSymmetricKey { get; set; }          // The encrypted key used to encrypt the contact.  can only be decrypted by semi Public Key


        public class BlockHeader
        {
            [JsonPropertyName("BlockId")]
            public required string BlockId { get; set; } = "";                       // Unique identifier for the block

            [JsonPropertyName("BlockType")]
            public required string BlockType { get; set; } = "";                       // "Reputation", "Transaction" or "Contact"

            [JsonPropertyName("BlockVersion")]
            public required string BlockVersion {  get; set; } = "";                     // Block Versions allow for deserialization of different blocks as the platform evolves.

            [JsonPropertyName("ContactVersion")]
            public string ContactVersion { get; set; } = "";                   // Contact versions would allow for deserialization of different contact styles as the platform evolves must be on the contact and the block.

            [JsonPropertyName("BlockCreationTime")]
            public required DateTime BlockCreationTime { get; set; } = new();                 // Creation time stamp

            [JsonPropertyName("LastUpdateTime")]
            public required DateTime LastUpdateTime { get; set; } = new();                // Time stamp of last Update to the block by validated user.

            [JsonPropertyName("EncryptionAlgorithm")]
            public required string EncryptionAlgorithm { get; set; } = "";              // Algorithm used for encryption (e.g. AES256, RSA2048, ECDsa)

            [JsonPropertyName("KeyUsagePolicies")]
            public required string? KeyUsagePolicies { get; set; }                // Policies for key usage

            [JsonPropertyName("BlockHash")]
            public string BlockHash { get; set; } = "UNKNOWN";                       // Hash of the block for integrity

            [JsonPropertyName("PublicSignatureKey")]
            public required byte[] PublicSignatureKey { get; set; }                  // This is the public key for verifying the signature of commits and the user.

            [JsonPropertyName("PublicEncryptionKey")]
            public required byte[] PublicEncryptionKey { get; set; }                  // This is the public key for encrypt messages to the user.

            [JsonPropertyName("GNCCertificate")]
            public required byte[] CNGCertificate { get; set; }                      // GNC Container Certificate for the Private Key, Used to validate application used correct security when storing privatekey. 

            [JsonPropertyName("PreviousHash")]
            public string PreviousHash { get; set; } = "";                      // Hash of the previous block

            // Calculates the hash for the block
            public string CalculateBlockHash()
            {
                string input = $"{BlockId}{PreviousHash}{BlockCreationTime}{EncryptionAlgorithm}{KeyUsagePolicies}";
                using var sha256 = SHA256.Create();
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }

            // Generates a unique block ID
            public static string GenerateBlockID()
            {
                    byte[] randomBytes = new byte[32]; 
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(randomBytes);
                    }
                    return Convert.ToBase64String(randomBytes); 
            }

            // Parses a block type from a string
            public static BlockType ParseBlockType(string type)
            {
                Enum.TryParse(type, out BlockType parsedEnum);
                return parsedEnum;
            }
        }


        // Creating a Contact Block
        public static Block CreateContactBlock(string previousHash, string encryptedContactData, EncryptionAlgorithm encryptionAlgorithm)
        {

                //Check to see if Keys exist.
                if (!ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PublicPersonalSignatureKey) || !ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PrivatePersonalSignatureKey) || !ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PublicPersonalEncryptionKey) || !ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PrivatePersonalEncryptionKey))
                {
                  throw new ArgumentException(nameof(ServiceAccountManager), "One or more Key was Missing You should run KeyGenerator.GeneratePersonalKeyPairSets(string exportPassword). A password will be needed to be included for exporting private keys later.");
                }

                DateTime creationTime = DateTime.Now;

                var header = new BlockHeader
                {
                    BlockId = BlockHeader.GenerateBlockID(),
                    BlockType = BlockType.Contact.ToString(),
                    BlockVersion = "1.0",
                    PreviousHash = previousHash,
                    BlockCreationTime = creationTime,
                    LastUpdateTime = creationTime,
                    EncryptionAlgorithm = encryptionAlgorithm.ToString(),
                    KeyUsagePolicies = "MESSAGE_ENCRYPTION_ONLY",
                    PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalSignatureKey),
                    PublicEncryptionKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalEncryptionKey),
                    CNGCertificate = SignatureGenerator.CreateSphereCNGCertificate(KeyGenerator.KeyType.PrivatePersonalEncryptionKey),
                };

                // Serialize and store contact data
                string serializedContactData = JsonSerializer.Serialize(encryptedContactData);

                header.BlockHash = header.CalculateBlockHash();


                return new Block
                {
                    Header = header,
                    EncryptedContact = serializedContactData,
                    EncryptedLocalSymmetricKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.EncryptedLocalSymmetricKey),
                };
        }

        // Checks if a block is a contact block
        public bool IsContactBlock(Block block)
        {
            return block?.Header?.BlockType != null &&
                   block.Header.BlockType == BlockType.Contact.ToString();
        }

        // Creating a Reputation Block
        public static Block CreateReputationBlock(string previousHash, string reputationData, EncryptionAlgorithm encryptionAlgorithm)
        {
            DateTime creationTime = DateTime.UtcNow;

            var header = new BlockHeader
            {
                BlockId = BlockHeader.GenerateBlockID(),
                BlockType = BlockType.Reputation.ToString(),
                BlockVersion = "1.0",
                PreviousHash = previousHash,
                BlockCreationTime = creationTime,
                LastUpdateTime = creationTime,
                EncryptionAlgorithm = encryptionAlgorithm.ToString(),
                KeyUsagePolicies = "MESSAGE_ENCRYPTION_ONLY",
                PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalSignatureKey),
                PublicEncryptionKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalEncryptionKey),
                CNGCertificate = SignatureGenerator.CreateSphereCNGCertificate(KeyGenerator.KeyType.PrivatePersonalEncryptionKey),
            };
            header.BlockHash = header.CalculateBlockHash();


            // Encrypt and store contact data
            string serializedContactData = JsonSerializer.Serialize(reputationData);

            return new Block
            {
                Header = header,
                ReputationBlock = reputationData,
                EncryptedLocalSymmetricKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.EncryptedLocalSymmetricKey),
            };
        }

        // Checks if a block is a reputation block
        public bool IsReputationBlock(Block block)
        {
            return block?.Header?.BlockType != null &&
                   block.Header.BlockType == BlockType.Reputation.ToString();
        }

        // Creating a Reputation Block
        public static Block CreateTransactionBlock(string previousHash, string transactionData, EncryptionAlgorithm encryptionAlgorithm)
        {
            DateTime creationTime = DateTime.UtcNow;

            var header = new BlockHeader
            {
                BlockId = BlockHeader.GenerateBlockID(),
                BlockType = BlockType.Transaction.ToString(),
                BlockVersion = "1.0",
                PreviousHash = previousHash,
                BlockCreationTime = creationTime,
                LastUpdateTime = creationTime,
                EncryptionAlgorithm = encryptionAlgorithm.ToString(),
                KeyUsagePolicies = "MESSAGE_ENCRYPTION_ONLY",
                PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalSignatureKey),
                PublicEncryptionKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalEncryptionKey),
                CNGCertificate = SignatureGenerator.CreateSphereCNGCertificate(KeyGenerator.KeyType.PrivatePersonalEncryptionKey),
            };

            header.BlockHash = header.CalculateBlockHash();

               SystemLogger.Log("Transaction Block Created");
            return new Block
            {
                Header = header,
                TransactionBlock = transactionData,
                EncryptedLocalSymmetricKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.EncryptedLocalSymmetricKey),
            };
        }

        public bool IsTransactionBlock(Block block)
        {
            return block?.Header?.BlockType != null &&
                   block.Header.BlockType == BlockType.Transaction.ToString();

            
        }

    }
}



