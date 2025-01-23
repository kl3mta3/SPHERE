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


    


