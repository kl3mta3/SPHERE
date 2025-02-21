using System.Security.Cryptography;
using SPHERE.Blockchain;
using SPHERE.Security;
using SPHERE.Configure.Logging;


namespace SPHERE.Configure
{
    /// <summary>
    /// Encryption is vital for the success of the system.  
    /// We use need to encrypt the contact with the Local Symmetric Key(LSK).
    /// We then need to encrypt the LSK with the Semi Public Key(SPK). This is added to the block. 
    /// 
    /// Only if provided with the SPK can a node or user decrypt the LSK and then the contact in the block.
    /// 
    /// We also encrpyt message to other nodes with thier public Node Signature key 
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
        public static byte[] EncryptPacketWithPublicKey(byte[] data, byte[] recipientPublicKey)
        {
            try
            {
                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";

                byte[] recipientSubjectPublicKey = ConvertCngPublicKeyToSubjectPublicKeyInfo(recipientPublicKey);

                if (isTesting)
                {
                 
                    byte[] sendersPrivateKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeEncryptionKey);
                 

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
                    byte[] sendersPrivateKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateNodeEncryptionKey);

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
        public static byte[] DecryptPacketWithPrivateKey(byte[] encryptedData, byte[] sendersPublicKey)
        {
            try
            {
              
                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";

                byte[] senderSubjectPublicKey = ConvertCngPublicKeyToSubjectPublicKeyInfo(sendersPublicKey);


                if (isTesting)
                {

                    byte[] recipientPrivateKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeEncryptionKey);
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

                    // Extract IV and Ciphertext
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

                    byte[] recipientPrivateKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeEncryptionKey);
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

                    // Extract IV and Ciphertext
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
    

        // Local Symmetric Keys(LSA) are used to Encrypt a contact. They are encrypted with a Semi Pulic Key(SPK) so only someone with the SBK can decrypt the LSK and in turn the contact. 
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


        public static byte[] ConvertCngPublicKeyToSubjectPublicKeyInfo(byte[] eccPublicBlob)
        {
            using var ecdh = new ECDiffieHellmanCng(CngKey.Import(eccPublicBlob, CngKeyBlobFormat.EccPublicBlob));
            return ecdh.PublicKey.ExportSubjectPublicKeyInfo();
        }
    }
}


    


