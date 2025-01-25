
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SPHERE;
using SPHERE.Configure;

namespace SPHERE.Blockchain
{
    public class Contact
    {
        public ContactMetaData MetaData { get; set; }               // Contacts needed MetaData.
        public ContactKeys Keys { get; set; }                       // Contacts needed Encryption keys. 


        public static Contact CreateNewContact(string displayName, string name, string blockId, string? avatarURL, string? description)
        {

            //Generate the set or Key Pairs needed  (Signature and Communication pair)
            KeyGenerator.GeneratePersonalKeyPairSets();
            var semiPublicKey = KeyGenerator.GenerateSymmetricKey();
            ServiceAccountManager.StoreKeyInContainerWithoutExport(semiPublicKey, "SPUBK");
            semiPublicKey = null;

            //used to encrypt the contact
            var localSymmetricKey = KeyGenerator.GenerateSymmetricKey();
            ServiceAccountManager.StoreKeyInContainerWithoutExport(localSymmetricKey, "RLSK");
            localSymmetricKey = null;

            //the LocalSymmetricKey is Encrypted with the SemiPublicKey and attached to the block so only approved people with the semiPublicKey can decrypt the EncryptedLocalSymetricKey and then decrypt the contact. 
            var encryptedLocalSymmetricKey = Encryption.EncryptLocalSymmetricKey(localSymmetricKey, semiPublicKey);
            ServiceAccountManager.StoreKeyInContainerWithoutExport(encryptedLocalSymmetricKey, "ELSK");
            encryptedLocalSymmetricKey = null;

            //Create a GNC Certificate for the PrivateCommunicationKey to verify correct standards are used. For Node application quality checks. (May remove later) 
            var GNCCert = SignatureGenerator.CreateSphereGNCCertificate("PRISIGK");
            ServiceAccountManager.StoreKeyInContainerWithoutExport(GNCCert, "GNCC");
            GNCCert = null;

            ContactKeys keys = new ContactKeys
            {
                PersonalCommKey = ServiceAccountManager.RetrieveKeyFromContainer("PUBCOMK"),
                PublicSignatureKey = ServiceAccountManager.RetrieveKeyFromContainer("PUBSIGK"),
                SemiPublicKey = ServiceAccountManager.RetrieveKeyFromContainer("SPUBK"),
                LocalSymmetricKey = ServiceAccountManager.RetrieveKeyFromContainer("RLSK")
            };

            ContactMetaData metaData = new ContactMetaData
            {
                DisplayName = displayName,
                Name = name,
                AvatarURLHash = avatarURL,
                Description = description,

            };

            Contact contact = new Contact
            {
                MetaData = metaData,
                Keys = keys,

            };
            return contact;
        }


        public static string BuildEncryptedContact(Contact contact)
        {

            var encryptedContact = Encryption.EncryptWithSymmetric(contact, contact.Keys.LocalSymmetricKey);

            return encryptedContact;

        }
        /// <summary>
        /// The contact is intented to be the core of a block.  It will be encrypted with a Local Symmentic Key before it is placed on the block.  
        /// The purpose is to allow for users to control their data, but also gain the security and decenteralization of a p2p DHT.
        /// 
        /// *Basic Information
        /// Basic Information like disply Name name and email, the general information you would give out and is on average already condidered publicly accessable. 
        /// *
        /// 
        /// **SSN
        /// Social Security Numbers are only stored as a salted Hash.  When needing to verify a users Identity a verification server can take the SSN and the key and verify that hash against the record, 
        /// then if Verified the server can Issue a Certificate of Proof the bank can maintain. 
        /// **
        /// 
        /// ***Accounts and Card numbers. 
        /// The long term idea is you can even store salted and Hash CC and Bank account Info.  The user when needing to purchase an item will use a secure server, they will provied their card info and their key,  
        /// the server will hash that and compair it against the one on the chain.  If verified the server will make a one way connection between the two accounts securing the account info inside only to the recipient and sender. 
        /// The merchant and even the verifying server do not have access.
        /// ***
        /// </summary>
        public class ContactMetaData()
        {
            public string DisplayName { get; set; }                     // User's display name
            public string Name { get; set; }                            // Users Name
            public string ContactVersion {  get; set; }                       // Contact versions would allow for deserialation of different contact styles as the platform evolves.
            public string? HashedSSN {  get; set; }                     // Users can provide a salted Hash of their SSN and this can be used later by applications to comparir it against the a hash of the ssn and key provided by the user. (Optional)
            public string? HashedCardNumber {  get; set; }              // Users can provide a salted Hash of their Card Number, this will by used by verification server when provided the cc and key by the user, if it can verify the hash it creates a 1 way payment tunnel from there to the merchants account. the merchant never sees the data (optional)
            public string? HashedAccountNumber {  get; set; }           // Users can provide a salted Hash of their Rccount, this will by used by verification server when provided the account number and key by the user, if it can verify the hash it creates a 1 way payment tunnel from there to the merchants account.(optional)
            public string? HashedRoutingNumber { get; set; }            // Users can provide a salted Hash of their Routing, this will by used by verification server when provided the routing number and key by the user, if it can verify the hash it creates a 1 way payment tunnel from there to the merchants account.(optional)
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
        }

    }
}
