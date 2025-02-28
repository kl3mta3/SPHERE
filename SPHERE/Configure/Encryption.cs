using System.Security.Cryptography;
using SPHERE.Blockchain;
using SPHERE.Security;
using SPHERE.Configure.Logging;
using System.Security;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;
using System.Security.Principal;
using System.Text.Json;
using System.Security.AccessControl;
using static SPHERE.Security.KeyGenerator;
using System.Xml.Linq;


namespace SPHERE.Configure
{
    /// <summary>
    /// Encryption is vital for the success of the system.  
    /// We use need to encrypt the contact with the Local Symmetric Key(LSK).
    /// We then need to encrypt the LSK with the Semi Public Key(SPK). This is added to the block. 
    /// 
    /// Only if provided with the SPK can a node or user decrypt the LSK and then the contact in the block.
    /// 
    /// We also encrypt message to other nodes with their public Node Signature key 
    /// We Decrypt message sent to the node that was encrypted with its public Node Signature Key. 
    /// 
    /// Contacts can also be used to encrypt a message with the Personal Key (PublicCommunicationKey) that allows only the contact to read it. 
    /// 
    /// The application used by a user can access messages sent them and decrypt it with their Private Communication key.
    /// 
    ///
    /// </summary>
    // Encryption/Decryption helper classes

    public static class Encryption
    {



        // The Local Symmetric Key is used to Encrypt the blockContact.
        public static byte[] EncryptWithSymmetric(Contact contactData, byte[] key)
        {
            byte[] convertedKey = key;

            string data = System.Text.Json.JsonSerializer.Serialize(contactData);
            using var aes = Aes.Create();
            aes.Key = convertedKey;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length); // Prepend IV to the encrypted data

            using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var writer = new StreamWriter(cryptoStream))
            {
                writer.Write(data);
            }

            return ms.ToArray(); // Return Base64-encoded encrypted data
        }

        public static Contact DecryptWithSymmetricKey(string encryptedData, string key)
        {
            byte[] convertedKey = Convert.FromBase64String(key);
            byte[] convertedEncryptedData = Convert.FromBase64String(encryptedData);

            using var aes = Aes.Create();

            // Extract IV from the encrypted data
            byte[] iv = new byte[16];
            Array.Copy(convertedEncryptedData, 0, iv, 0, iv.Length);
            aes.IV = iv;
            aes.Key = convertedKey;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(convertedEncryptedData, iv.Length, convertedEncryptedData.Length - iv.Length);
            using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var reader = new StreamReader(cryptoStream);
            string decryptedData = reader.ReadToEnd();

            // Deserialize the contact from the data.
            return System.Text.Json.JsonSerializer.Deserialize<Contact>(decryptedData);
        }

        //Encrypt with a personal(public) Key Provides a secretKey to Validate its use. 
        public static byte[] EncryptPacketWithPublicKey(Node node, byte[] data, byte[] recipientPublicKey)
        {
            try
            {
                PrivateKeyManager keyManager = node.KeyManager;
                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";

                byte[] recipientSubjectPublicKey = recipientPublicKey;

                if (isTesting)
                {
                    byte[] sendersPrivateKey = keyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PrivateNodeEncryptionKey);
                 

                    using var recipientKey = ECDiffieHellman.Create();
                    recipientKey.ImportSubjectPublicKeyInfo(recipientSubjectPublicKey, out _);


                    // Create sender key pair and import sender's private key
                    using var senderKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                    senderKeyPair.ImportPkcs8PrivateKey(sendersPrivateKey, out _);

                    // Derive shared secret using recipient's actual public key
                    byte[] sharedSecret = senderKeyPair.DeriveKeyMaterial(recipientKey.PublicKey);

                    // Hash shared secret to create AES key
                    using var sha256 = SHA256.Create();
                    byte[] aesKey = sha256.ComputeHash(sharedSecret);

                  

                    using var aes = Aes.Create();
                    aes.KeySize = 256;
                    aes.Key = aesKey;
                    aes.GenerateIV();
                    aes.Padding = PaddingMode.PKCS7;
                    byte[] iv = aes.IV;

                    using var encryptor = aes.CreateEncryptor();
                    byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);


                    // Construct final message: [IV] + [Encrypted Data]
                    byte[] result = new byte[iv.Length + encryptedData.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);

                  
                    return result;


                }
                else
                {
                    byte[] sendersPrivateKey = keyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PrivateNodeEncryptionKey);

                    using var recipientKey = ECDiffieHellman.Create();
                    recipientKey.ImportSubjectPublicKeyInfo(recipientSubjectPublicKey, out _);


                    // Create sender key pair and import sender's private key
                    using var senderKeyPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
                    senderKeyPair.ImportPkcs8PrivateKey(sendersPrivateKey, out _);

                    // Derive shared secret using recipient's actual public key
                    byte[] sharedSecret = senderKeyPair.DeriveKeyMaterial(recipientKey.PublicKey);

                    // Hash shared secret to create AES key
                    using var sha256 = SHA256.Create();
                    byte[] aesKey = sha256.ComputeHash(sharedSecret);



                    using var aes = Aes.Create();
                    aes.KeySize = 256;
                    aes.Key = aesKey;
                    aes.GenerateIV();
                    aes.Padding = PaddingMode.PKCS7;
                    byte[] iv = aes.IV;

                    using var encryptor = aes.CreateEncryptor();
                    byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);


                    // Construct final message: [IV] + [Encrypted Data]
                    byte[] result = new byte[iv.Length + encryptedData.Length];
                    Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    Buffer.BlockCopy(encryptedData, 0, result, iv.Length, encryptedData.Length);


                    return result;


                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"EncryptPacketWithPublicKey: Encryption error: {ex.Message}");
                throw;
            }
        }

        //Decrypt with the Private Key Stored in the CNG Container and the shared secret
        public static byte[] DecryptPacketWithPrivateKey(Node node, byte[] encryptedData, byte[] sendersPublicKey)
        {
            try
            {

                PrivateKeyManager privateKeyManager = node.KeyManager;
                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";

                byte[] senderSubjectPublicKey = sendersPublicKey;


                if (isTesting)
                {

                    byte[] recipientPrivateKey = privateKeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PrivateNodeEncryptionKey);
                    using var recipientKeyPair = ECDiffieHellman.Create();
                    recipientKeyPair.ImportPkcs8PrivateKey(recipientPrivateKey, out _); 

                    // Ensure the sender's public key is in SubjectPublicKeyInfo format
                    using var senderKeyPair = ECDiffieHellman.Create();
                    senderKeyPair.ImportSubjectPublicKeyInfo(senderSubjectPublicKey, out _); 

                    // Derive the shared secret using recipient’s private key and sender’s public key
                    byte[] sharedSecret = recipientKeyPair.DeriveKeyMaterial(senderKeyPair.PublicKey);

                    // Hash the shared secret to create AES key
                    using var sha256 = SHA256.Create();
                    byte[] aesKey = sha256.ComputeHash(sharedSecret);

                    // Extract IV and Cipher text
                    byte[] iv = new byte[16];
                    byte[] ciphertext = new byte[encryptedData.Length - 16];

                    Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
                    Buffer.BlockCopy(encryptedData, 16, ciphertext, 0, ciphertext.Length);

                    using var aes = Aes.Create();
                    aes.Key = aesKey;
                    aes.IV = iv;
                    aes.Padding = PaddingMode.PKCS7;

                    using var decryptor = aes.CreateDecryptor();
                    return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
                else
                {

                    byte[] recipientPrivateKey = privateKeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey);
                    using var recipientKeyPair = ECDiffieHellman.Create();
                    recipientKeyPair.ImportPkcs8PrivateKey(recipientPrivateKey, out _);

                    // Ensure the sender's public key is in SubjectPublicKeyInfo format
                    using var senderKeyPair = ECDiffieHellman.Create();
                    senderKeyPair.ImportSubjectPublicKeyInfo(senderSubjectPublicKey, out _);

                    // Derive the shared secret using recipient’s private key and sender’s public key
                    byte[] sharedSecret = recipientKeyPair.DeriveKeyMaterial(senderKeyPair.PublicKey);

                    // Hash the shared secret to create AES key
                    using var sha256 = SHA256.Create();
                    byte[] aesKey = sha256.ComputeHash(sharedSecret);

                    // Extract IV and Cipher text
                    byte[] iv = new byte[16];
                    byte[] ciphertext = new byte[encryptedData.Length - 16];

                    Buffer.BlockCopy(encryptedData, 0, iv, 0, 16);
                    Buffer.BlockCopy(encryptedData, 16, ciphertext, 0, ciphertext.Length);

                    using var aes = Aes.Create();
                    aes.Key = aesKey;
                    aes.IV = iv;
                    aes.Padding = PaddingMode.PKCS7;

                    using var decryptor = aes.CreateDecryptor();
                    return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"DecryptPacketWithPrivateKey: Decryption error: {ex.Message}");
                throw;
            }
        }
    
        // Local Symmetric Keys(LSA) are used to Encrypt a contact. They are encrypted with a Semi Public Key(SPK) so only someone with the SBK can decrypt the LSK and in turn the contact. 
        public static byte[] EncryptLocalSymmetricKey(byte[] localSymmetricKey, byte[] semiPublicKey)
        {
            // Convert the keys to byte arrays

            using var aes = Aes.Create();
            aes.Key = semiPublicKey;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length); // Prepend IV to the encrypted data

            using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(localSymmetricKey, 0, localSymmetricKey.Length);
            }

            return ms.ToArray(); // Return Base64-encoded encrypted data
        }

        // Decrypts the Local Symmetric Key(LSK) with the Semi Public Key(SPK)
        public static string DecryptLocalSymmetricKey(byte[] encryptedLocalSymmetricKey, byte[] semiPublicKey)
        {
            // Convert the keys and encrypted data to byte arrays


            using var aes = Aes.Create();

            // Extract the IV from the encrypted data
            byte[] iv = new byte[16];
            Array.Copy(encryptedLocalSymmetricKey, 0, iv, 0, iv.Length);
            aes.IV = iv;
            aes.Key = semiPublicKey;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(encryptedLocalSymmetricKey, iv.Length, encryptedLocalSymmetricKey.Length - iv.Length);
            using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var reader = new BinaryReader(cryptoStream);

            byte[] decryptedKeyBytes = reader.ReadBytes((int)(ms.Length - iv.Length));

            return Convert.ToBase64String(decryptedKeyBytes); // Return Base64-encoded localSymmetricKey
        }

        // Encrypts data using a local symmetric key and a salt
        public static byte[] EncryptLocalSymmetricKeyWithSalt(byte[] localKey, byte[] data, byte[] salt)
        {
            // Derive a strong encryption key using PBKDF2
            using var keyDerivation = new Rfc2898DeriveBytes(localKey, salt, 100_000, HashAlgorithmName.SHA256);
            byte[] derivedKey = keyDerivation.GetBytes(32); // AES-256 key

            using var aes = Aes.Create();
            aes.Key = derivedKey;
            aes.GenerateIV(); // Generate random IV

            using var encryptorAES = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();

            ms.Write(aes.IV, 0, aes.IV.Length); // Prepend IV to the encrypted data

            using (var cryptoStream = new CryptoStream(ms, encryptorAES, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
            }

            return ms.ToArray(); // Return the encrypted byte array
        }

        // Decrypts data using a local symmetric key and a salt
        public static byte[] DecryptLocalSymmetricKeyWithSalt(byte[] localKey, byte[] encryptedData, byte[] salt)
        {
            try
            {
                // Derive the encryption key using PBKDF2
                using var keyDerivation = new Rfc2898DeriveBytes(localKey, salt, 100_000, HashAlgorithmName.SHA256);
                byte[] derivedKey = keyDerivation.GetBytes(32); // AES-256 key

                using var aes = Aes.Create();
                aes.Key = derivedKey;

                // Extract IV (first 16 bytes of the encrypted data)
                byte[] iv = encryptedData.Take(16).ToArray();
                aes.IV = iv;

                using var decryptorAES = aes.CreateDecryptor(aes.Key, aes.IV);
                using var ms = new MemoryStream(encryptedData.Skip(16).ToArray());
                using var cryptoStream = new CryptoStream(ms, decryptorAES, CryptoStreamMode.Read);
                using var decryptedStream = new MemoryStream();

                cryptoStream.CopyTo(decryptedStream);
                return decryptedStream.ToArray(); // Return the decrypted data
            }
            catch(Exception ex)
            {

                SystemLogger.Log($"Error-DecryptLocalSymmetricKeyWithSalt: Failed to decrypt Key. Reason:{ex.Message}");
                return null;
            }
        }

        // Converts a CNG public key to SubjectPublicKeyInfo format
       

     

    }

    public class KeyParts
    {
       public byte[] Alpha { get; set; } 
       public  byte[] Beta { get; set; }
       public  byte[] Delta { get; set; }
       public int SplitIndex { get; set; } // Added split index for tracking the starting point
    }

    public class EncryptedKeyParts
    {
        [JsonPropertyName("Alpha")]
        public byte Alpha { get; set; } // The known starting point for decryption
        [JsonPropertyName("AllParts")]
        public byte[][] AllParts { get; set; } // Contains both real and fake encrypted key parts
        [JsonPropertyName("SplitIndex")]
        public int SplitIndex { get; set; } // Added split index for tracking the starting point
    }

    public class NodeKeyStorageFile
    {
        [JsonPropertyName("NodePublicSignatureKey")]
        public string NodePublicSignatureKey { get; set; }

        [JsonPropertyName("NodePublicEncryptionKey")]
        public string NodePublicEncryptionKey { get; set; }

        [JsonPropertyName("NodePrivateSignatureKey")]
        public string NodePrivateSignatureKey { get; set; }

        [JsonPropertyName("NodePrivateEncryptionKey")]
        public string NodePrivateEncryptionKey { get; set; }

        // 🔹 Convert Base64 string to `byte[]`
        public byte[] GetByteArray(string key) => string.IsNullOrEmpty(key) ? null : Convert.FromBase64String(key);

        // 🔹 Convert `byte[]` to Base64 and store as string
        public void SetByteArray(ref string property, byte[] value) => property = value != null ? Convert.ToBase64String(value) : null;
    }

    internal class PrivateKeyManager
    {
        // Stores the private Contact in Memory
        private SecureString PrivatePersonalEncryptionKey { get; set; } = new SecureString();
        private SecureString PrivatePersonalSignatureKey { get; set; } = new SecureString();
        private SecureString PublicPersonalEncryptionKey { get; set; } = new SecureString();
        private SecureString PublicPersonalSignatureKey { get; set; } = new SecureString();
        private SecureString SemiPublicKey { get; set; } = new SecureString();
        private SecureString LocalSymmetricKey { get; set; } = new SecureString();
        private SecureString EncryptedLocalSymmetricKey { get; set; } = new SecureString();

        private readonly string BaseKeyFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Sphere\\Container\\");
        internal string KeyFilePath {  get; private set; } = "";

        //-----New Encryption Method for the BlockContact-----\\
        private static KeyParts DynamicLabeledKeySplit(byte[] fullKey)
        {
            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(fullKey);

            // Minimum 32 bits (4 bytes) per part
            int minPartSize = 32;
            int remainingBits = 256 - (minPartSize * 3);

            // Dynamically determine sizes
            int partASize = (hash[0] % (remainingBits + 1)) + minPartSize;
            int partBSize = (hash[1] % (remainingBits - (partASize - minPartSize) + 1)) + minPartSize;
            int partCSize = 256 - (partASize + partBSize);

            // Perform the split
            byte[] part1 = fullKey.Take(partASize / 8).ToArray();
            byte[] part2 = fullKey.Skip(partASize / 8).Take(partBSize / 8).ToArray();
            byte[] part3 = fullKey.Skip((partASize + partBSize) / 8).ToArray();

            // Deterministically assign labels based on hash byte parity

            KeyParts labeledParts = new KeyParts();
            int splitIndex = hash[2] % 3; // Determines the first key to use

            switch (splitIndex)
            {
                case 0:
                    labeledParts.Alpha = part1;
                    labeledParts.Beta = part2;
                    labeledParts.Delta = part3;

                    break;
                case 1:
                    labeledParts.Alpha = part2;
                    labeledParts.Beta = part3;
                    labeledParts.Delta = part1;
                    break;
                case 2:
                    labeledParts.Alpha = part3;
                    labeledParts.Beta = part1;
                    labeledParts.Delta = part2;
                    break;
            }

            labeledParts.SplitIndex = splitIndex; // Store the split index for later reconstruction
            return labeledParts;
        }

        // Retrieves the private Contact key from memory
        internal byte[] GetPersonalKey(KeyGenerator.KeyType keyType)
        {
            if (keyType != KeyGenerator.KeyType.PrivatePersonalEncryptionKey || keyType != KeyGenerator.KeyType.PrivatePersonalSignatureKey || keyType != KeyGenerator.KeyType.PublicPersonalEncryptionKey || keyType != KeyGenerator.KeyType.PublicPersonalSignatureKey || keyType != KeyGenerator.KeyType.SemiPublicKey || keyType != KeyGenerator.KeyType.LocalSymmetricKey || keyType != KeyGenerator.KeyType.EncryptedLocalSymmetricKey)
            {
                SystemLogger.Log($"Error-GetPrivateContactKey: KeyType is not a Private Personal Key");
                return null; 
            }

            SecureString secureKey = keyType switch
            {
                KeyGenerator.KeyType.PrivatePersonalEncryptionKey => PrivatePersonalEncryptionKey,
                KeyGenerator.KeyType.PrivatePersonalSignatureKey => PrivatePersonalSignatureKey,
                KeyGenerator.KeyType.PublicPersonalSignatureKey => PublicPersonalSignatureKey,
                KeyGenerator.KeyType.PublicPersonalEncryptionKey => PublicPersonalEncryptionKey,
                KeyGenerator.KeyType.SemiPublicKey => SemiPublicKey,
                KeyGenerator.KeyType.EncryptedLocalSymmetricKey => EncryptedLocalSymmetricKey,
                KeyGenerator.KeyType.LocalSymmetricKey => LocalSymmetricKey,
                _ => null
            };

            if (secureKey == null || secureKey.Length == 0)
            {
                throw new InvalidOperationException("Private key is not loaded in memory.");
            }

            // Convert SecureString to String
            IntPtr ptr = Marshal.SecureStringToGlobalAllocUnicode(secureKey);
            try
            {
                return Convert.FromBase64String(Marshal.PtrToStringUni(ptr));
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr); 
            }
        }

        // Retrieves the private Node key from memory
        internal byte[] GetNodeKey(KeyGenerator.KeyType keyType)
        {
            SystemLogger.Log($"Debug-GetNodeKey: Getting Node Key...@.@");

            try
            {
                if (!File.Exists(KeyFilePath))
                {
                    SystemLogger.Log($"Error-GetNodeKey: Error Key File did not exist. ({KeyFilePath})");
                    return null;
                }

                NodeKeyStorageFile keyfile = LoadKeyFile();

                if (keyfile == null)
                {
                    SystemLogger.Log($"Error-GetNodeKey: Key file could not be loaded.");
                    return null;
                }

                // Convert Base64 strings to byte arrays
                byte[] keyToReturn = keyType switch
                {
                    KeyGenerator.KeyType.PublicNodeSignatureKey => ConvertKeyFromBase64(keyfile.NodePublicSignatureKey),
                    KeyGenerator.KeyType.PublicNodeEncryptionKey => ConvertKeyFromBase64(keyfile.NodePublicEncryptionKey),
                    KeyGenerator.KeyType.PrivateNodeSignatureKey => ConvertKeyFromBase64(keyfile.NodePrivateSignatureKey),
                    KeyGenerator.KeyType.PrivateNodeEncryptionKey => ConvertKeyFromBase64(keyfile.NodePrivateEncryptionKey),
                    _ => null
                };

                if (keyToReturn == null || keyToReturn.Length == 0)
                {
                    SystemLogger.Log($"Error-GetNodeKey: Retrieved key is NULL or EMPTY.");
                    return null;
                }

                return keyToReturn;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-GetNodeKey: Failed to Get the Key. Reason: {ex.Message}");
                return null;
            }
        }

        private byte[] ConvertKeyFromBase64(string base64Key)
        {
            if (string.IsNullOrEmpty(base64Key))
            {
                return null;
            }

            try
            {
                return Convert.FromBase64String(base64Key);
            }
            catch (FormatException ex)
            {
                SystemLogger.Log($"Error-ConvertKeyFromBase64: Invalid Base64 format. Reason: {ex.Message}");
                return null;
            }
        }

        //Securely Wipe Key from Storage
        private void SecureWipeKeyStorage(ref NodeKeyStorageFile keyfile)
        {
            try
            {
                if (keyfile == null) return;

                // Function to wipe Base64-encoded keys safely
                string WipeBase64String(string base64Key)
                {
                    if (string.IsNullOrEmpty(base64Key)) return null;
                    byte[] keyBytes = Convert.FromBase64String(base64Key);
                    RandomNumberGenerator.Fill(keyBytes);
                    return Convert.ToBase64String(keyBytes);
                }

                // Overwrite each key securely
                keyfile.NodePublicSignatureKey = WipeBase64String(keyfile.NodePublicSignatureKey);
                keyfile.NodePublicEncryptionKey = WipeBase64String(keyfile.NodePublicEncryptionKey);
                keyfile.NodePrivateSignatureKey = WipeBase64String(keyfile.NodePrivateSignatureKey);
                keyfile.NodePrivateEncryptionKey = WipeBase64String(keyfile.NodePrivateEncryptionKey);

                // Nullify the reference
                keyfile = null;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-SecureWipeKeyStorage: Failed to wipe Key from storage, Reason:{ex.Message}");
            }
        }

        // Securely wipes the private Contact key from memory
        internal void WipePersonalKeyFromMemory(KeyGenerator.KeyType keyType)
        {
            try
            {
                if (keyType != KeyGenerator.KeyType.PrivateNodeEncryptionKey || keyType != KeyGenerator.KeyType.PrivateNodeSignatureKey || keyType != KeyGenerator.KeyType.LocalSymmetricKey || keyType != KeyGenerator.KeyType.SemiPublicKey)
                {
                    return;
                }

                switch (keyType)
                {

                    case KeyGenerator.KeyType.PrivateNodeEncryptionKey:

                        PrivatePersonalEncryptionKey?.Dispose();
                        PrivatePersonalEncryptionKey= new SecureString();
                        break;

                    case KeyGenerator.KeyType.PrivateNodeSignatureKey:

                        PrivatePersonalSignatureKey?.Dispose();
                        PrivatePersonalSignatureKey = new SecureString();
                        break;


                    case KeyGenerator.KeyType.SemiPublicKey:

                        SemiPublicKey?.Dispose();
                        SemiPublicKey = new SecureString();
                        break;

                    case KeyGenerator.KeyType.LocalSymmetricKey:

                        LocalSymmetricKey?.Dispose();
                        LocalSymmetricKey = new SecureString();
                        break;

                }
            }
            catch(Exception ex)
            {
                SystemLogger.Log($"Error- WipePersonalKeyFromMemory: Failed to wipe Key from memory, Reason:{ex.Message}");
            }
        }

        //Set the Private Personal Key in Memory 
        internal void SetPrivatePersonalKey(byte[] key, KeyGenerator.KeyType keyType)
        {
            if (keyType != KeyGenerator.KeyType.PrivateNodeEncryptionKey &&
                keyType != KeyGenerator.KeyType.PrivateNodeSignatureKey &&
                keyType != KeyGenerator.KeyType.LocalSymmetricKey &&
                keyType != KeyGenerator.KeyType.SemiPublicKey)
            {
                return;
            }

            try
            {
                if (key == null || key.Length == 0)
                {
                    SystemLogger.Log("Error- SetPrivatePersonalKey: Key cannot be null or empty.");
                    return;
                }

                SecureString newSecureString = new SecureString();
                foreach (byte b in key)
                {
                    newSecureString.AppendChar((char)b);
                }
                newSecureString.MakeReadOnly();

                switch (keyType)
                {
                    case KeyGenerator.KeyType.PrivateNodeEncryptionKey:
                        PrivatePersonalEncryptionKey?.Dispose();
                        PrivatePersonalEncryptionKey = newSecureString;
                        break;

                    case KeyGenerator.KeyType.PrivateNodeSignatureKey:
                        PrivatePersonalSignatureKey?.Dispose();
                        PrivatePersonalSignatureKey = newSecureString;
                        break;

                    case KeyGenerator.KeyType.SemiPublicKey:
                        SemiPublicKey?.Dispose();
                        SemiPublicKey = newSecureString;
                        break;

                    case KeyGenerator.KeyType.LocalSymmetricKey:
                        LocalSymmetricKey?.Dispose();
                        LocalSymmetricKey = newSecureString;
                        break;
                }

                // Wipe the original key from memory
                Array.Clear(key, 0, key.Length);
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error- SetPrivatePersonalKey: Failed to Set Key Reason: {ex.Message}");
            }
        }

        //Set Node Encryption Path
        internal void SetNodeEncryptionFilePath(Node node)
        {
            if (!Directory.Exists(BaseKeyFilePath))
            {
                Directory.CreateDirectory(BaseKeyFilePath);
            }

            string fist12ofNodeID= node.Peer.NodeId.Length >= 12 ? node.Peer.NodeId.Substring(0, 12) : node.Peer.NodeId;
            string nodePath = Path.Combine(BaseKeyFilePath + fist12ofNodeID + ".dat");
            node.KeyManager.KeyFilePath = nodePath;
        }


        // Encrypts the key parts and returns the encrypted parts
        internal EncryptedKeyParts EncryptPersonalKeyParts(byte[] fullKey, string password, string pin)
        {
            KeyParts realParts = DynamicLabeledKeySplit(fullKey);

            try
            {

                using var sha256 = SHA256.Create();

                // Create 3-4 fake key parts filled with random data
                byte[][] fakeParts = new byte[3][];
                for (int i = 0; i < fakeParts.Length; i++)
                {
                    fakeParts[i] = RandomNumberGenerator.GetBytes(realParts.Alpha.Length); // Fake junk data
                }

                // Mix real parts with fake parts in a random order
                byte[][] allParts = new byte[6][];
                allParts[0] = realParts.Alpha;
                allParts[1] = realParts.Beta;
                allParts[2] = realParts.Delta;
                allParts[3] = fakeParts[0];
                allParts[4] = fakeParts[1];
                allParts[5] = fakeParts[2];


                // Encrypt each part with its dependencies
                byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] combinedPassPin = passwordBytes.Concat(pinBytes).ToArray();
                byte[] combinedKeySalt = allParts[0].Concat(combinedPassPin).ToArray();

                byte[] passSalt = sha256.ComputeHash(combinedPassPin);
                byte[] keySalt = sha256.ComputeHash(combinedKeySalt);

                byte[] encryptedC = Encryption.EncryptLocalSymmetricKeyWithSalt(allParts[1], allParts[2], sha256.ComputeHash(allParts[0]));
                byte[] modifiedB = InjectVerificationBit(allParts[1], encryptedC[0]);
                byte[] encryptedB = Encryption.EncryptLocalSymmetricKeyWithSalt(allParts[0], allParts[1], passSalt);
                byte[] modifiedA = InjectVerificationBit(allParts[0], encryptedB[0]);
                byte[] encryptedA = Encryption.EncryptLocalSymmetricKeyWithSalt(modifiedA, passwordBytes, pinBytes);

                allParts[0] = encryptedA;
                allParts[1] = encryptedB;
                allParts[2] = encryptedC;
                ShuffleArray(allParts);

                return new EncryptedKeyParts
                {
                    Alpha = encryptedA[0],
                    SplitIndex = realParts.SplitIndex,
                    AllParts = allParts
                };
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-EncryptPersonalKeyParts: Failed to Encrypt Personal Key Parts. Reason: {ex.Message}");
                return null;
            }
        }

        // Decrypts the key parts and reconstructs the full key
        internal byte[] DecryptKeyWithFakeDetection(EncryptedKeyParts encryptedParts, string password, string pin)
        {
            try
            {
                using var sha256 = SHA256.Create();

                byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] combinedPassPin = passwordBytes.Concat(pinBytes).ToArray();
               
                byte[] alphaKeyEncrypted = FindMatchingPart(encryptedParts.AllParts, encryptedParts.Alpha);
                
                byte[] decryptedA = Encryption.DecryptLocalSymmetricKeyWithSalt(passwordBytes, alphaKeyEncrypted, pinBytes);
                byte[] passSalt = sha256.ComputeHash(combinedPassPin);
                
                var (AlphaFollowerBit, keyACleaned) = ExtractVerificationBit(decryptedA);
                byte[] Alpha = keyACleaned;
                byte[] keySalt = sha256.ComputeHash(Alpha.Concat(passSalt).ToArray());
                byte[] nextKey = FindMatchingPart(encryptedParts.AllParts, AlphaFollowerBit);

                if (nextKey == null)
                {
                    throw new Exception("No matching part found! Possible data corruption or incorrect verification bit.");
                }


                byte[] decryptedB = Encryption.DecryptLocalSymmetricKeyWithSalt(Alpha, nextKey, passSalt);
                var (BetaFollowerBit, keyBCleaned) = ExtractVerificationBit(decryptedB);
                nextKey = FindMatchingPart(encryptedParts.AllParts, BetaFollowerBit);
                byte[] Beta = keyBCleaned;

                byte[] decryptedC = Encryption.DecryptLocalSymmetricKeyWithSalt(Beta, nextKey, keySalt);

                return CombineByteArrays(decryptedA, decryptedB, decryptedC, encryptedParts.SplitIndex);
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-DecryptKeyWithFakeDetection: Failed to decrypt the key. Reason:{ex.Message}");

                return null;
            }
        }

        // Shuffle the Key Array
        internal void ShuffleArray(byte[][] array)
        {
            try
            {
                Random rng = new Random();
                int n = array.Length;
                for (int i = n - 1; i > 0; i--)
                {
                    int j = rng.Next(i + 1);
                    (array[i], array[j]) = (array[j], array[i]); // Swap elements
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-ShuffleArray: Failed to Shuffle Array. Reason {ex.Message}");
            }
        }

        // Injects a verification bit into the data
        internal byte[] InjectVerificationBit(byte[] targetData, byte verificationByte)
        {
            try
            {

                byte[] modifiedData = new byte[targetData.Length + 1];
                int insertPosition = targetData.Length / 4; // Example: Inject after 1/4 of the data
                Array.Copy(targetData, 0, modifiedData, 0, insertPosition);
                modifiedData[insertPosition] = verificationByte; // Insert verification bit
                Array.Copy(targetData, insertPosition, modifiedData, insertPosition + 1, targetData.Length - insertPosition);
                return modifiedData;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-InjectVerificationBit: Failed to Inject VerificationBit. Reason:{ex.Message}");
                return null;
            }
        }

        // Extracts the verification bit from the data
        internal (byte verificationByte, byte[] restoredData) ExtractVerificationBit(byte[] modifiedData)
        {
            try
            {
               
                if (modifiedData == null || modifiedData.Length < 4)
                {
                    SystemLogger.Log("Error-ExtractVerificationBit: Input data is null or too short.");
                    return (0, null);
                }

                int insertPosition = modifiedData.Length / 4;

                
                if (insertPosition < 0 || insertPosition >= modifiedData.Length)
                {
                    SystemLogger.Log("Error-ExtractVerificationBit: Insert position out of range.");
                    return (0, null);
                }

                byte verificationByte = modifiedData[insertPosition];

                byte[] restoredData = new byte[modifiedData.Length - 1];

                
                Array.Copy(modifiedData, 0, restoredData, 0, insertPosition);
                Array.Copy(modifiedData, insertPosition + 1, restoredData, insertPosition, restoredData.Length - insertPosition);

                return (verificationByte, restoredData);
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-ExtractVerificationBit: Failed to Extract VerificationBit. Reason:{ex.Message}");
              
                return (0, new byte[0]);
            }
        }

        // Finds the matching part based on the verification bit
        internal byte[] FindMatchingPart(byte[][] allParts, byte verificationBit)
        {
            try
            {
                foreach (byte[] part in allParts)
                {
                    if (part.Length > 0 && part[0] == verificationBit) // Check if the first byte matches
                    {
                        return part; // Found the correct part
                    }
                }
                throw new Exception("No matching part found! Possible data corruption or incorrect verification bit.");
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-InjectVerificationBit: Failed to Inject VerificationBit. Reason:{ex.Message}");
                return null;
            }
        }


        internal byte[] CombineByteArrays(byte[] first, byte[] second, byte[] third, int splitIndex)
        {
            byte[][] parts = new byte[3][];
            try
            {
                // Reassemble based on the stored SplitIndex
                switch (splitIndex)
                {
                    case 0:
                        parts[0] = first;  // Alpha (originally part1)
                        parts[1] = second; // Beta (originally part2)
                        parts[2] = third;  // Delta (originally part3)
                        break;
                    case 1:
                        parts[0] = second; // Alpha (originally part2)
                        parts[1] = third;  // Beta (originally part3)
                        parts[2] = first;  // Delta (originally part1)
                        break;
                    case 2:
                        parts[0] = third;  // Alpha (originally part3)
                        parts[1] = first;  // Beta (originally part1)
                        parts[2] = second; // Delta (originally part2)
                        break;
                    default:
                        throw new ArgumentException("Invalid split index provided.");
                }

                using var ms = new MemoryStream();
                ms.Write(parts[0], 0, parts[0].Length);
                ms.Write(parts[1], 0, parts[1].Length);
                ms.Write(parts[2], 0, parts[2].Length);
                return ms.ToArray();
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-CombineByteArrays: Failed to Combine Byte Arrays. Reason:{ex.Message}");
                return null;
            }
        }

        //Encrypt and Store the Node Key Locally
        internal void StoreNodeKeyLocally(byte[] key, KeyGenerator.KeyType keyType)
        {
            try
            {
                SystemLogger.Log($"Debug-StoreKeyLocally: Attempting to Store a Key of type {keyType}");

                if (key == null || key.Length == 0)
                {
                    SystemLogger.Log($"Error-StoreKeyLocally: Received an empty or NULL key.");
                    return;
                }

                NodeKeyStorageFile newKeyStorage;

                if (File.Exists(KeyFilePath))
                {
                    SystemLogger.Log($"Debug-StoreKeyLocally: File Path Exists - Loading existing file.");
                    newKeyStorage = LoadKeyFile() ?? new NodeKeyStorageFile();
                }
                else
                {
                    SystemLogger.Log($"Debug-StoreKeyLocally: No File Existed. Creating new File...");
                    newKeyStorage = new NodeKeyStorageFile();
                }

                SystemLogger.Log($"Debug-StoreKeyLocally: Storing Keys:");

                switch (keyType)
                {
                    case KeyGenerator.KeyType.PublicNodeSignatureKey:
                        newKeyStorage.NodePublicSignatureKey = Convert.ToBase64String(key);
                        break;
                    case KeyGenerator.KeyType.PublicNodeEncryptionKey:
                        newKeyStorage.NodePublicEncryptionKey = Convert.ToBase64String(key);
                        break;
                    case KeyGenerator.KeyType.PrivateNodeSignatureKey:
                        newKeyStorage.NodePrivateSignatureKey = Convert.ToBase64String(key);
                        break;
                    case KeyGenerator.KeyType.PrivateNodeEncryptionKey:
                        newKeyStorage.NodePrivateEncryptionKey = Convert.ToBase64String(key);
                        break;
                }

                SaveKeyStorage(newKeyStorage);
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-StoreKeyLocally: Failed to store Key {keyType}. Reason: {ex.Message}");
            }
        }

        //Load the Key Storage File.
        internal NodeKeyStorageFile LoadKeyFile()
        {
            try
            {
                SystemLogger.Log($"Debug-LoadKeyFile: Loading Key File...");

                if (!File.Exists(KeyFilePath))
                {
                    SystemLogger.Log($"Error-LoadKeyFile: Key file does not exist at {KeyFilePath}");
                    return null;
                }

                byte[] jsonData = File.ReadAllBytes(KeyFilePath);

                if (jsonData == null || jsonData.Length == 0)
                {
                    SystemLogger.Log($"Error-LoadKeyFile: Key file exists but is empty at {KeyFilePath}");
                    return null;
                }

                byte[] decryptedData = Encryption.DecryptLocalSymmetricKeyWithSalt(GenerateUserKey(), jsonData, GenerateUserSalt());

                if (decryptedData == null || decryptedData.Length == 0)
                {
                    SystemLogger.Log($"Error-LoadKeyFile: Decryption failed, resulting in empty data.");
                    return null;
                }

                NodeKeyStorageFile file = JsonSerializer.Deserialize<NodeKeyStorageFile>(decryptedData);

                if (file == null)
                {
                    SystemLogger.Log($"Error-LoadKeyFile: JSON Deserialization failed.");
                    return null;
                }

                SystemLogger.Log($"Debug-LoadKeyFile: Successfully deserialized key file.");
                return file;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-LoadKeyFile: Failed to load Key file. Reason {ex.Message}");
                return null;
            }
        }

        //Save the KeyStoreFile to disk
        private void SaveKeyStorage(NodeKeyStorageFile keyStorage)
        {
            try
            {
                if (keyStorage == null)
                {
                    SystemLogger.Log($"Error-SaveKeyStorage: Attempted to save a NULL key storage object.");
                    return;
                }

                SystemLogger.Log($"Debug-SaveKeyStorage: Saving Node Key Storage:");

                // Prevent saving if all keys are NULL
                if (string.IsNullOrEmpty(keyStorage.NodePublicSignatureKey) &&
                    string.IsNullOrEmpty(keyStorage.NodePublicEncryptionKey) &&
                    string.IsNullOrEmpty(keyStorage.NodePrivateSignatureKey) &&
                    string.IsNullOrEmpty(keyStorage.NodePrivateEncryptionKey))
                {
                    SystemLogger.Log($"Error-SaveKeyStorage: All keys are NULL. Skipping save operation.");
                    return;
                }

                byte[] jsonData = JsonSerializer.SerializeToUtf8Bytes(keyStorage);

                byte[] encryptedData = Encryption.EncryptLocalSymmetricKeyWithSalt(GenerateUserKey(), jsonData, GenerateUserSalt());

                if (encryptedData == null || encryptedData.Length == 0)
                {
                    SystemLogger.Log($"Error-LoadKeyFile: Decryption failed, resulting in empty data.");
                    return;
                }

                File.WriteAllBytes(KeyFilePath, encryptedData);
                SystemLogger.Log($"Debug-SaveKeyStorage: Successfully wrote Key to file.");

                SetSecureFilePermissions(KeyFilePath);
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-SaveKeyStorage: Failed to Save KeyStorage. Reason:{ex.Message}");
            }
        }

        //Set the security setting of the Key File
        private void SetSecureFilePermissions(string filePath)
        {
            try
            {

                var fileInfo = new FileInfo(filePath);
                var security = fileInfo.GetAccessControl();

                security.SetAccessRule(new FileSystemAccessRule(
                    Environment.UserName,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

                fileInfo.SetAccessControl(security);
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-SetSecureFilePermissions: Failed to set file protections. Reason {ex.Message}");
            }
        }

        //Generate a user specific key for encryption
        public byte[] GenerateUserKey()
        {
            try
            {

                string userName = Environment.UserName; // Get Windows username
                string userSID = WindowsIdentity.GetCurrent().User.Value; // More unique user ID

                using var sha256 = SHA256.Create();
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(userName + userSID));
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-GenerateUserKey:Failed to Generate User Key. Reason:{ex.Message}");
                throw new InvalidOperationException("Failed to generate user key, encryption aborted.", ex);
            }
        }

        //Generate a user specific salt for encryption
        public byte[] GenerateUserSalt()
        {
            try
            {
                string userDomain = Environment.UserDomainName; // Windows domain
                string systemDrive = Environment.GetFolderPath(Environment.SpecialFolder.System); // System root path

                using var sha256 = SHA256.Create();
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(userDomain + systemDrive));
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-GenerateUserSalt:Failed to Generate User Salt. Reason:{ex.Message}");
                throw new InvalidOperationException("Failed to generate user salt, encryption aborted.", ex);
            }
        }

        internal byte[] UseKeyInStorageContainer(Node node, KeyGenerator.KeyType keyType)
        {
            try
            {
                SystemLogger.Log($"Debug-UseKeyInStorageContainer: Attempting to get Key.");
                byte[] keyData= null;

                PrivateKeyManager privateKeyManager = node.KeyManager;

                switch (keyType)
                {
                    case KeyType.PrivateNodeEncryptionKey:
                        keyData = privateKeyManager.GetNodeKey(KeyType.PrivateNodeEncryptionKey);
                        break;

                    case KeyType.PrivateNodeSignatureKey:
                        keyData = privateKeyManager.GetNodeKey(KeyType.PrivateNodeSignatureKey);
                        break;

                    case KeyType.PublicNodeEncryptionKey:
                        keyData = privateKeyManager.GetNodeKey(KeyType.PublicNodeEncryptionKey);
                        break;

                    case KeyType.PublicNodeSignatureKey:
                        keyData = privateKeyManager.GetNodeKey(KeyType.PublicNodeSignatureKey);
                        break;

                    case KeyType.PrivatePersonalEncryptionKey:
                        keyData = privateKeyManager.GetPersonalKey(KeyType.PrivatePersonalEncryptionKey);
                        break;

                    case KeyType.PrivatePersonalSignatureKey:
                        keyData = privateKeyManager.GetPersonalKey(KeyType.PrivatePersonalSignatureKey);
                        break;

                    case KeyType.PublicPersonalEncryptionKey:
                        keyData = privateKeyManager.GetPersonalKey(KeyType.PrivatePersonalEncryptionKey);
                        break;

                    case KeyType.PublicPersonalSignatureKey:
                        keyData = privateKeyManager.GetPersonalKey(KeyType.PrivatePersonalSignatureKey);
                        break;

                    case KeyType.SemiPublicKey:
                        keyData = privateKeyManager.GetPersonalKey(KeyType.SemiPublicKey);
                        break;

                    case KeyType.LocalSymmetricKey:
                        keyData = privateKeyManager.GetPersonalKey(KeyType.LocalSymmetricKey);
                        break;

                    case KeyType.EncryptedLocalSymmetricKey:
                        keyData = privateKeyManager.GetPersonalKey(KeyType.LocalSymmetricKey);
                        break;

                    default:
                        SystemLogger.Log($"Error-UseKeyInStorageContainer: Invalid key type: {keyType}");
                        return null;
                }
                if (keyData == null || keyData.Length == 0)
                {
                    SystemLogger.Log($"Error-UseKeyInStorageContainer: Retrieved key is null or empty for keyType: {keyType}");
                    throw new Exception($"Key retrieval failed for {keyType}, keyData is null or empty.");
                }
                return keyData;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-UseKeyInStorageContainer: Error retrieving key '{keyType.ToString()}' Reason: {ex.Message}");
                throw;
            }
        }
    }


}




    


