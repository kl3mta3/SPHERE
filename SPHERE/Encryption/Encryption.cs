using System;
using Microsoft.Win32;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.Xml;
using System.Windows.Input;
using System.IO;
using SPHERE.Blockchain;
using System.Security.AccessControl;

namespace SPHERE
{
    // Encryption/Decryption helper classes
    public static class Encryption
    {
        // The Local Symmetric Key is used to Eccrypt the blockContact.
        public static string EncryptWithSymmetric(BlockContact contactData, string key)
        {
            byte[] convertedKey = Convert.FromBase64String(key);

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

            return Convert.ToBase64String(ms.ToArray()); // Return Base64-encoded encrypted data
        }
        public static BlockContact DecryptWithSymmetricKey(string encryptedData, string key)
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
            return System.Text.Json.JsonSerializer.Deserialize<BlockContact>(decryptedData);
        }

        //Encrypt with a personal(public) Key Provides a secretKey to Validate its use. 
        private static (byte[] encryptedData, byte[] sharedSecret) EncryptWithPersonalKey(string data, string personalKey)
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ecdh.ImportSubjectPublicKeyInfo(Convert.FromBase64String(personalKey), out _);

            // Generate a shared secret using the recipient's public key
            byte[] sharedSecret = ecdh.DeriveKeyMaterial(ecdh.PublicKey);

            // Use the shared secret to encrypt data (e.g., AES)
            using var aes = Aes.Create();
            aes.Key = sharedSecret;
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var writer = new StreamWriter(cs))
            {
                writer.Write(data);
            }

            return (ms.ToArray(), aes.IV);

        }

        //Decrypt with the Private Key Stored in the CNG Container and the shared secret
        private static string DecryptWithPrivateKey(string privateKey, string encryptedData, byte[] sharedSecret)
        {
            byte[] encryptedDataByteArray = Convert.FromBase64String(encryptedData);


            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ecdh.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);

            // Derive the shared secret
            byte[] derivedKey = ecdh.DeriveKeyMaterial(ecdh.PublicKey);

            // Decrypt the data (e.g., AES)
            using var aes = Aes.Create();
            aes.Key = derivedKey;
            aes.IV = sharedSecret;
            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using var ms = new MemoryStream(encryptedDataByteArray);
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var reader = new StreamReader(cs);
            return reader.ReadToEnd();

        }

        // The Encryption Keys are stored in Local CNG Containers.  Those containers are only accessable by the local Service account the App Creates and runs on. 
        public static void StoreKeyInContainer(string key, string keyName)
        {
            string AppId = AppIdentifier.GetOrCreateAppIdentifier();

            // Ensure the service account exists
            ServiceAccountManager.ServiceAccountLogon();

            try
            {
                // Convert the key from Base64
                byte[] convertedKey = Convert.FromBase64String(key);

                // Define key creation parameters
                var creationParameters = new CngKeyCreationParameters
                {
                    ExportPolicy = CngExportPolicies.None, // Prevents key export
                    KeyUsage = CngKeyUsages.Signing | CngKeyUsages.Decryption // Restrict to signing and decryption
                };

                // Create the key
                using var cngKey = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParameters);

                // Store the application-specific identifier
                cngKey.SetProperty(new CngProperty("AppId", Encoding.UTF8.GetBytes(AppId), CngPropertyOptions.None));

                // Optional: Store additional data securely within the container
                cngKey.SetProperty(new CngProperty("KeyData", convertedKey, CngPropertyOptions.None));

                Console.WriteLine("Private key stored securely with app-specific restrictions.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing private key: {ex.Message}");
                throw;
            }
        }
        public static string RetrieveKeyFromContainer(string keyName)
        {
            try
            {
                // Open the key from the container
                using var cngKey = CngKey.Open(keyName);

                // Retrieve the application-specific identifier (optional)
                var appIdProperty = cngKey.GetProperty("AppId", CngPropertyOptions.None);
                string appId = Encoding.UTF8.GetString(appIdProperty.GetValue());
                Console.WriteLine($"Retrieved AppId: {appId}");

                // Retrieve the stored key data
                var keyDataProperty = cngKey.GetProperty("KeyData", CngPropertyOptions.None);
                string keyData = Convert.ToBase64String(keyDataProperty.GetValue());

                return keyData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving key from container: {ex.Message}");
                throw;
            }
        }

        // Local Symmetric Keys(LSA) are used to Encrypt a contact. They are encrypted with a Semi Pulic Key(SPK) so only someone with the SBK can decrypt the LSK and in turn the contact. 
        public static string EncryptLocalSymmetricKey(string localSymmetricKey, string semiPublicKey)
        {
            // Convert the keys to byte arrays
            byte[] localKeyBytes = Convert.FromBase64String(localSymmetricKey);
            byte[] semiPublicKeyBytes = Convert.FromBase64String(semiPublicKey);

            using var aes = Aes.Create();
            aes.Key = semiPublicKeyBytes;
            aes.GenerateIV();

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length); // Prepend IV to the encrypted data

            using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cryptoStream.Write(localKeyBytes, 0, localKeyBytes.Length);
            }

            return Convert.ToBase64String(ms.ToArray()); // Return Base64-encoded encrypted data
        }
        public static string DecryptLocalSymmetricKey(string encryptedLocalSymmetricKey, string semiPublicKey)
        {
            // Convert the keys and encrypted data to byte arrays
            byte[] encryptedKeyBytes = Convert.FromBase64String(encryptedLocalSymmetricKey);
            byte[] semiPublicKeyBytes = Convert.FromBase64String(semiPublicKey);

            using var aes = Aes.Create();

            // Extract the IV from the encrypted data
            byte[] iv = new byte[16];
            Array.Copy(encryptedKeyBytes, 0, iv, 0, iv.Length);
            aes.IV = iv;
            aes.Key = semiPublicKeyBytes;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(encryptedKeyBytes, iv.Length, encryptedKeyBytes.Length - iv.Length);
            using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var reader = new BinaryReader(cryptoStream);

            byte[] decryptedKeyBytes = reader.ReadBytes((int)(ms.Length - iv.Length));

            return Convert.ToBase64String(decryptedKeyBytes); // Return Base64-encoded localSymmetricKey
        }
    }
}


    


