using SPHERE.Configure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SPHERE.Blockchain;
using SPHERE.Configure.Logging;

namespace SPHERE.Security
{
    /// <summary>
    /// We use two kinds of keys. 
    /// 
    /// --ECC Curve Pair --
    /// A contact(user) has two key pairs. 
    /// 
    /// *Public Communication Key(Personal Key)/ a Private Communication Key (encryptiong KEY). 
    /// This pair is used for communication at the contact level.  
    /// The Personal communication Key is stored in the contact and used to encrypt messages only the contact owner with the Private Communication Key can decrypt.
    /// *
    /// 
    /// **Public Signature Key/Private Signature Key.
    /// The Public Signature Key is attached to the block and used to verify the signature of the Contact creator/owner that has the private associated key.
    /// **
    /// 
    /// A Node also has a Pair of both . 
    /// *The Public Node Signature Key is provided by the node to allow for communication to it to be encrypted so that only it can read the responses with its Private Signature Key. 
    ///  The Encrypting Key is used to allow others to encrypt messages to the node. 
    /// *
    /// 
    /// --Symmetric Keys--
    /// These are used to create the Semi Public Key and Local Symmetric Key.
    /// 
    /// * Semi Pubic Key(SPK) is used to encrypt the Local Symmetric Key Before it is placed on a block. 
    ///   it is then provided to anyone you wish to have access to the contact.
    /// *
    /// 
    /// **Local Symmetric Key(LSK) is used to encrypt the contact before it is added to the block.  It is then encrypted by the Semi Public Key and added to the block itself. 
    /// 
    /// </summary>
    public class KeyGenerator
    {
        public enum KeyType
        {
            PublicPersonalSignatureKey,
            PrivatePersonalSignatureKey,
            PublicPersonalEncryptionKey,
            PrivatePersonalEncryptionKey,
            PublicNodeSignatureKey,
            PrivateNodeSignatureKey,
            PublicNodeEncryptionKey,
            PrivateNodeEncryptionKey,
            EncryptedLocalSymmetricKey,
            LocalSymmetricKey,
            SemiPublicKey,
            CNGCert,
            //PublicTestNodeSignatureKey,
            //PrivateTestNodeSignatureKey,
            //PublicTestNodeEncryptionKey,
            //PrivateTestNodeEncryptionKey,

        }
        internal static void GeneratePersonalKeyPairSets(Password exportPassword)
        {
            using var signaturePair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var encryptPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            PrivateKeyManager PrivateKeyManager = new();
            if (signaturePair == null || encryptPair == null)
            {
                throw new InvalidOperationException("Failed to create cryptographic key pairs.");
            }

            var privateSignatureKey = signaturePair.ExportPkcs8PrivateKey();
            var publicSignatureKey = signaturePair.ExportSubjectPublicKeyInfo();
            var privateEncryptionKey = encryptPair.ExportPkcs8PrivateKey();
            var publicEncryptionKey = encryptPair.ExportSubjectPublicKeyInfo();

            try
            {
                PrivateKeyManager.SetPrivatePersonalKey(privateSignatureKey, KeyType.PrivatePersonalSignatureKey);
                PrivateKeyManager.SetPrivatePersonalKey(publicSignatureKey, KeyType.PublicPersonalSignatureKey);
                PrivateKeyManager.SetPrivatePersonalKey(privateEncryptionKey, KeyType.PrivatePersonalEncryptionKey);
                PrivateKeyManager.SetPrivatePersonalKey(publicEncryptionKey, KeyType.PublicPersonalEncryptionKey);


                //ServiceAccountManager.StorePrivateKeyInContainerWithExportPlainText(privateSignatureKey, KeyType.PrivatePersonalSignatureKey, exportPassword);
                //ServiceAccountManager.StoreKeyInContainerWithExport(publicSignatureKey, KeyType.PublicPersonalSignatureKey);
                //ServiceAccountManager.StorePrivateKeyInContainerWithExportPlainText(privateEncryptionKey, KeyType.PrivatePersonalEncryptionKey, exportPassword);
                //ServiceAccountManager.StoreKeyInContainerWithExport(publicEncryptionKey, KeyType.PublicPersonalEncryptionKey);

            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Key generation failed.", ex);
            }
            finally
            {

                ClearSensitiveData(privateSignatureKey);
                ClearSensitiveData(publicSignatureKey);
                ClearSensitiveData(privateEncryptionKey);
                ClearSensitiveData(publicEncryptionKey);

                privateSignatureKey = null;
                publicSignatureKey = null;
                publicEncryptionKey = null;
                privateEncryptionKey = null;
            }

        }

        internal static void GenerateNodeKeyPairs(Node node)
        {
            SystemLogger.Log($"Debug-GenerateNodeKeyPairs :Generating Node Key Pair.");

            using var nodeSigPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var nodeEncPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

            PrivateKeyManager privateKeyManager = node.KeyManager;

            if (nodeSigPair == null || nodeEncPair == null)
            {
                throw new InvalidOperationException("Failed to create cryptographic key pairs.");
            }

            var privateSigKey = nodeSigPair.ExportPkcs8PrivateKey();
            var publicSigKey = nodeSigPair.ExportSubjectPublicKeyInfo();
            var privateEncKey = nodeEncPair.ExportPkcs8PrivateKey();
            var publicEncKey = nodeEncPair.ExportSubjectPublicKeyInfo();

            try
            {
                privateKeyManager.StoreNodeKeyLocally(privateSigKey, KeyType.PrivateNodeSignatureKey);
                privateKeyManager.StoreNodeKeyLocally(publicSigKey, KeyType.PublicNodeSignatureKey);
                privateKeyManager.StoreNodeKeyLocally(privateEncKey, KeyType.PrivateNodeEncryptionKey);
                privateKeyManager.StoreNodeKeyLocally(publicEncKey, KeyType.PublicNodeEncryptionKey);           
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Key generation failed.", ex);
            }
            finally
            {

                ClearSensitiveData(privateEncKey);
                ClearSensitiveData(publicEncKey);
                ClearSensitiveData(privateSigKey);
                ClearSensitiveData(publicSigKey);

                privateEncKey = null;
                publicEncKey = null;
                privateSigKey = null;
                publicSigKey = null;
                SystemLogger.Log($"Debug-GenerateNodeKeyPairs :Node Key Pairs Generated Successfully.");
            }
        }

        internal static string CreateVerificationKey(string privateKey, string salt)
        {
            // Create the verification key (VK) from the private key
            using var hkdf = new HMACSHA256(Convert.FromBase64String(privateKey));
            byte[] verificationKey = hkdf.ComputeHash(Encoding.UTF8.GetBytes(salt));
            return Convert.ToBase64String(verificationKey);
        }

        internal static byte[] GenerateSymmetricKey()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            return ecdh.DeriveKeyMaterial(ecdh.PublicKey);
        }

        internal static void ClearSensitiveData(byte[] data)
        {
            if (data != null)
            {
                Array.Clear(data, 0, data.Length); // Overwrite with zeroes
            }
        }
    }
}
