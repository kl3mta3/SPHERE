﻿using SPHERE.Configure;
using SPHERE.Security;


namespace SPHERE.Blockchain
{
    public class Contact
    {
        public ContactMetaData MetaData { get; set; }               // Contacts needed MetaData.
        public ContactKeys Keys { get; set; }                       // Contacts needed Encryption keys. 
        public EncryptedKeyParts KeySignatureParts { get; set; }    // Contacts Private key is encrypted and stored in parts with noise
        public EncryptedKeyParts KeyEncryptionParts { get; set; }   // Contacts Private key is encrypted and stored in parts with noise
        public List<(byte[], byte[])> AuthenticationData = new();   // Hashes user for User Authentication and VAlidation for Password reset and recovery.

        /// <summary>
        /// !!!
        /// To Create a contact and Generate Pairs of needed Private Keys, A password is needed to be passed in.  This is a string meeting Requirements.  (Needs Upper, Lower, Number, Symbol, and to be between 8-64 characters.)
        /// User Password.CreatePasswordFromString(string password) to generate a password from a string or Password.GenerateRandomPassword(int length) defaults to 16char.
        /// <param name="displayName"></param>
        /// <param name="name"></param>
        /// <param name="blockId"></param>
        /// <param name="avatarURL"></param>
        /// <param name="description"></param>
        /// <param name="privateKeyPassword"></param>
        /// !!!
        /// <returns></returns>
        /// </summary>
        public static Contact CreateNewContact(Node node, string displayName, string name, string blockId, string? avatarURL, string? description, Password privateKeyPassword)
        {
            PrivateKeyManager PrivateKeyManager = new();
            //Generate the set or Key Pairs needed  (Signature and Communication pair)
            KeyGenerator.GeneratePersonalKeyPairSets(privateKeyPassword);

            var semiPublicKey = KeyGenerator.GenerateSymmetricKey();
            PrivateKeyManager.SetPrivatePersonalKey(semiPublicKey, KeyGenerator.KeyType.SemiPublicKey);

            //used to encrypt the contact
            var localSymmetricKey = KeyGenerator.GenerateSymmetricKey();
            PrivateKeyManager.SetPrivatePersonalKey(localSymmetricKey, KeyGenerator.KeyType.LocalSymmetricKey);

            //the LocalSymmetricKey is Encrypted with the SemiPublicKey and attached to the block so only approved people with the semiPublicKey can decrypt the EncryptedLocalSymetricKey and then decrypt the contact. 
            var encryptedLocalSymmetricKey = Encryption.EncryptLocalSymmetricKey(localSymmetricKey, semiPublicKey);
            PrivateKeyManager.SetPrivatePersonalKey(encryptedLocalSymmetricKey, KeyGenerator.KeyType.EncryptedLocalSymmetricKey);
          

            ContactKeys keys = new ContactKeys
            {
                PublicPersonalEncryptionKey = PrivateKeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicPersonalEncryptionKey),
                PublicPersonalSignatureKey = PrivateKeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicPersonalSignatureKey),
                SemiPublicKey = semiPublicKey,
                LocalSymmetricKey = localSymmetricKey
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


        public static byte[] BuildEncryptedContact(Contact contact)
        {

            var encryptedContact = Encryption.EncryptWithSymmetric(contact, contact.Keys.LocalSymmetricKey);

            return encryptedContact;

        }

        /// <summary>
        /// The contact is intended to be the core of a block.  It will be encrypted with a Local Symmetric Key before it is placed on the block.  
        /// The purpose is to allow for users to control their data, but also gain the security and decentralization of a p2p DHT.
        /// 
        /// *Basic Information
        /// Basic Information like display Name and email, the general information you would give out and is on average already considered publicly accessable. 
        /// *
        /// 
        /// **SSN
        /// Social Security Numbers are only stored as a salted Hash.  When needing to verify a users Identity a verification server can take the SSN and the key and verify that hash against the record, 
        /// then if Verified the server can Issue a Certificate of Proof the bank can maintain. 
        /// **
        /// 
        /// ***Accounts and Card numbers. 
        /// The long term idea is you can even store salted and Hash CC and Bank account Info.  The user when needing to purchase an item will use a secure server, they will provied their card info and their key,  
        /// the server will hash that and compare it against the one on the chain.  If verified the server will make a one way connection between the two accounts securing the account info inside only to the recipient and sender. 
        /// The merchant and even the verifying server do not have access.
        /// ***
        /// </summary>
        /// 
        public class ContactMetaData()
        {
            public string DisplayName { get; set; }                     // User's display name
            public string Name { get; set; }                            // Users Name
            public string ContactVersion {  get; set; }                 // Contact versions would allow for deserialization of different contact styles as the platform evolves.
            public string? HashedSSN {  get; set; }                     // Users can provide a salted Hash of their SSN and this can be used later by applications to comparir it against the a hash of the ssn and key provided by the user. (Optional)
            public string? HashedCardNumber {  get; set; }              // Users can provide a salted Hash of their Card Number, this will by used by verification server when provided the cc and key by the user, if it can verify the hash it creates a 1 way payment tunnel from there to the merchants account. the merchant never sees the data (optional)
            public string? HashedAccountNumber {  get; set; }           // Users can provide a salted Hash of their Recount, this will by used by verification server when provided the account number and key by the user, if it can verify the hash it creates a 1 way payment tunnel from there to the merchants account.(optional)
            public string? HashedRoutingNumber { get; set; }            // Users can provide a salted Hash of their Routing, this will by used by verification server when provided the routing number and key by the user, if it can verify the hash it creates a 1 way payment tunnel from there to the merchants account.(optional)
            public string? Language { get; set; }                       // Users Preferred Language (optional)
            public string? Email { get; set; }                          // Users Preferred Contact email (optional)
            public string? PhoneNumber { get; set; }                    // Users Preferred Phone Number. (optional)
            public string? AvatarURLHash { get; set; }                  // Hash of the avatar URL stored on a secure server (optional)
            public string? Description { get; set; }                    // Short description or additional contact info (optional)
        }

        public class ContactKeys()
        {
            public byte[] SemiPublicKey { get; set; }                   // Semi-public key
            public byte[] LocalSymmetricKey { get; set; }               // Unencrypted Local Symmetric code used to encrypt the Contact. 
            public byte[] PublicPersonalEncryptionKey { get; set; }                 // Personal Communication key for encrypting messages only the user can decrypt
            public byte[] PublicPersonalSignatureKey { get; set; }              // Used to verify signatures created with the PrivateSignatureKey
        }

    }
}
