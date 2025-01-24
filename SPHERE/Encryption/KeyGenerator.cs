using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace SPHERE.Configure
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
        public static void GeneratePersonalKeyPairSets()
        {
            using var signaturePair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var encryptPair = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

            var privateSignatureKey = signaturePair.ExportPkcs8PrivateKey();
            var publicSignatureKey = signaturePair.ExportSubjectPublicKeyInfo();
            var privateCommunicationKey = encryptPair.ExportPkcs8PrivateKey();
            var publicCommunicationKey = encryptPair.ExportSubjectPublicKeyInfo();

            try
            {
                string publicSignatureKeyBase64 = Convert.ToBase64String(publicSignatureKey);
                string privateSignatureKeyBase64 = Convert.ToBase64String(privateSignatureKey);
                string publicCommunicationKeyBase64 = Convert.ToBase64String(publicCommunicationKey);
                string privateCommunicationKeyBase64 = Convert.ToBase64String(privateCommunicationKey);

                ServiceAccountManager.StoreKeyInContainer(privateSignatureKeyBase64, "PRIPERSGNK");
                ServiceAccountManager.StoreKeyInContainer(publicSignatureKeyBase64, "PUBPERSGNK");
                ServiceAccountManager.StoreKeyInContainer(privateCommunicationKeyBase64, "PRIPERCOMK");
                ServiceAccountManager.StoreKeyInContainer(publicCommunicationKeyBase64, "PUBPERCOMK");

                privateSignatureKeyBase64 = null;
                publicSignatureKeyBase64 = null;
                publicCommunicationKeyBase64 = null;
                privateCommunicationKeyBase64 = null;
            }
            finally
            {

                ClearSensitiveData(privateSignatureKey);
                ClearSensitiveData(publicSignatureKey);
                ClearSensitiveData(privateCommunicationKey);
                ClearSensitiveData(publicCommunicationKey);

                privateSignatureKey = null;
                publicSignatureKey = null;
                publicCommunicationKey = null;
                privateCommunicationKey = null;
            }

        }

        public static void GenerateNodeKeyPairs()
        {

            using var nodeSigPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var nodeEncPair= ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

            var privateSigKey = nodeSigPair.ExportPkcs8PrivateKey();
            var publicSigKey = nodeSigPair.ExportSubjectPublicKeyInfo();
            var privateEncKey = nodeEncPair.ExportPkcs8PrivateKey();
            var publicEncKey = nodeEncPair.ExportSubjectPublicKeyInfo();


            try
            {
                string publicSigKeyBase64 = Convert.ToBase64String(publicSigKey);
                string privateKeyBase64 = Convert.ToBase64String(privateSigKey);
                string publicEncKeyBase64 = Convert.ToBase64String(publicEncKey);
                string privateEncKeyBase64 = Convert.ToBase64String(privateEncKey);

                ServiceAccountManager.StoreKeyInContainer(privateKeyBase64, "PRINODSIGK");
                ServiceAccountManager.StoreKeyInContainer(publicSigKeyBase64, "PUBNODSIGK");

                ServiceAccountManager.StoreKeyInContainer(privateKeyBase64, "PRINODENCK");
                ServiceAccountManager.StoreKeyInContainer(privateEncKeyBase64, "PUBNODENCK");

                privateKeyBase64 = null;
                publicSigKeyBase64 = null;
                privateEncKeyBase64 = null;
                publicEncKeyBase64 = null;
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
            }
        }

        public static string CreateVerificationKey(string privateKey, string salt)
        {
            // Create the verification key (VK) from the private key
            using var hkdf = new HMACSHA256(Convert.FromBase64String(privateKey));
            byte[] verificationKey = hkdf.ComputeHash(Encoding.UTF8.GetBytes(salt));
            return Convert.ToBase64String(verificationKey);
        }

        public static string GenerateSymmetricKey()
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            return Convert.ToBase64String(ecdh.DeriveKeyMaterial(ecdh.PublicKey));
        }

        public static void ClearSensitiveData(byte[] data)
        {
            if (data != null)
            {
                Array.Clear(data, 0, data.Length); // Overwrite with zeroes
            }
        }
    }
}
