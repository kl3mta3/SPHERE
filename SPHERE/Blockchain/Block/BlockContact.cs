
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SPHERE;

namespace SPHERE.Blockchain
{
    public class BlockContact
    {
        public ContactMetaData MetaData { get; set; }               // Contacts needed MetaData.
        public ContactKeys Keys { get; set; }                       // Contacts needed Encryption keys. 


        public static BlockContact CreateNewContact(string displayName, string name, string blockId, string? avatarURL, string? description)
        {

            //Generate the set or Key Pairs needed  (Signature and Communication pair)
            KeyGenerator.GeneratePersonalKeyPairSets();
            var semiPublicKey = KeyGenerator.GenerateSymmetricKey();
            Encryption.StoreKeyInContainer(semiPublicKey, "SPUBK");
            semiPublicKey = null;

            //used to encrypt the contact
            var localSymmetricKey = KeyGenerator.GenerateSymmetricKey();
            Encryption.StoreKeyInContainer(localSymmetricKey, "RLSK");
            localSymmetricKey = null;

            //the LocalSymmetricKey is Encrypted with the SemiPublicKey and attached to the block so only approved people with the semiPublicKey can decrypt the EncryptedLocalSymetricKey and then decrypt the contact. 
            var encryptedLocalSymmetricKey = Encryption.EncryptLocalSymmetricKey(localSymmetricKey, semiPublicKey);
            Encryption.StoreKeyInContainer(encryptedLocalSymmetricKey, "ELSK");
            encryptedLocalSymmetricKey = null;

            //Create a GNC Certificate for the PrivateCommunicationKey to verify correct standards are used. For Node application quality checks. (May remove later) 
            var GNCCert = SignatureGenerator.CreateSphereGNCCertificate("PRISIGK");
            Encryption.StoreKeyInContainer(GNCCert, "GNCC");
            GNCCert = null;

            ContactKeys keys = new ContactKeys
            {
                PersonalCommKey = Encryption.RetrieveKeyFromContainer("PUBCOMK"),
                PublicSignatureKey = Encryption.RetrieveKeyFromContainer("PUBSIGK"),
                SemiPublicKey = Encryption.RetrieveKeyFromContainer("SPUBK"),
                LocalSymmetricKey = Encryption.RetrieveKeyFromContainer("RLSK")
            };

            ContactMetaData metaData = new ContactMetaData
            {
                DisplayName = displayName,
                Name = name,
                AvatarURLHash = avatarURL,
                Description = description,

            };

            BlockContact contact = new BlockContact
            {
                MetaData = metaData,
                Keys = keys,

            };
            return contact;
        }


        public static string BuildEncryptedContact(BlockContact contact)
        {

            var encryptedContact = Encryption.EncryptWithSymmetric(contact, contact.Keys.LocalSymmetricKey);

            return encryptedContact;

        }

        public class ContactMetaData()
        {
            public string DisplayName { get; set; }                     // User's display name
            public string Name { get; set; }                            // Users Name
            public string? Language { get; set; }                       // Users Prefered Language (optional)
            public string? Email { get; set; }                          // Users Prefered Contact email (optional)
            public string? PhoneNumber { get; set; }                    // Users Prefered Phone Number. (optional)
            public string? AvatarURLHash { get; set; }                  // Hash of the avatar URL stored on a secure server (optional)
            public string? Description { get; set; }                    // Short description or additional contact info (optional)
        }

        public class ContactKeys()
        {
            public string SemiPublicKey { get; set; }                   // Semi-public key
            public string LocalSymmetricKey { get; set; }               // Unencrypted Local Symetric code used to encrypt the Contact. 
            public string PersonalCommKey { get; set; }                 // Personal Communication key for encrypting messages only the user can decrypt
            public string PublicSignatureKey { get; set; }              // Used to verify signatures created with the PrivateSignatureKey


            public string Name { get; set; }
        }



    }
}
