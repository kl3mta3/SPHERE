using System.Security.Cryptography;
using System.Text;


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

        }
        public static void GeneratePersonalKeyPairSets(Password exportPassword)
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

                ServiceAccountManager.StorePrivateKeyInContainerWithExportPlainText(privateSignatureKeyBase64, KeyType.PrivatePersonalSignatureKey, exportPassword);
                ServiceAccountManager.StoreKeyInContainerWithExport(publicSignatureKeyBase64, KeyType.PublicPersonalSignatureKey);
                ServiceAccountManager.StorePrivateKeyInContainerWithExportPlainText(privateCommunicationKeyBase64, KeyType.PrivatePersonalEncryptionKey, exportPassword);
                ServiceAccountManager.StoreKeyInContainerWithExport(publicCommunicationKeyBase64, KeyType.PublicPersonalEncryptionKey);

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

                ServiceAccountManager.StoreKeyInContainerWithoutExport(privateKeyBase64, KeyType.PrivateNodeSignatureKey);
                ServiceAccountManager.StorePublicKeyInContainerWithExportPlainText(publicSigKeyBase64, KeyType.PublicNodeSignatureKey);

                ServiceAccountManager.StoreKeyInContainerWithoutExport(privateKeyBase64, KeyType.PrivateNodeEncryptionKey);
                ServiceAccountManager.StoreKeyInContainerWithExport(privateEncKeyBase64, KeyType.PublicNodeEncryptionKey);

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

    /// <summary>
    /// This class is used to create a secure password format. the password is used to export private keys.
    /// </summary>
    public class Password
    {
        private readonly string _value;

        // Public accessor for the password string
        public string Value => _value;

        // Constructor that enforces password constraints
        public Password(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password cannot be null or empty.");
            }

            if (password.Length < 8 || password.Length > 64)
            {
                throw new ArgumentException("Password must be between 8 and 64 characters long.");
            }

            if (!HasRequiredCharacters(password))
            {
                throw new ArgumentException("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.");
            }

            _value = password;
        }

        // Helper method to validate password character requirements
        private static bool HasRequiredCharacters(string password)
        {
            bool hasUpper = false;
            bool hasLower = false;
            bool hasDigit = false;
            bool hasSpecial = false;

            foreach (char c in password)
            {
                if (char.IsUpper(c)) hasUpper = true;
                else if (char.IsLower(c)) hasLower = true;
                else if (char.IsDigit(c)) hasDigit = true;
                else if (!char.IsLetterOrDigit(c)) hasSpecial = true;

                if (hasUpper && hasLower && hasDigit && hasSpecial) return true;
            }

            return false;
        }

        // Optional: Override ToString to hide the password value
        public override string ToString()
        {
            return "********"; // Mask the password when displayed
        }

        public static Password CreatePasswordFromString(string input)
        {
            // Check for null, empty, or whitespace input
            if (string.IsNullOrWhiteSpace(input))
            {
                throw new ArgumentException("Password cannot be null, empty, or consist only of whitespace.");
            }

            // Check length requirements
            if (input.Length < 8 || input.Length > 64)
            {
                throw new ArgumentException("Password must be between 8 and 64 characters long.");
            }

            // Check character requirements
            if (!HasRequiredCharacters(input))
            {
                throw new ArgumentException("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.");
            }

            // If all requirements are met, create and return a Password object
            return new Password(input);
        }

        public static Password GenerateRandomPassword(int length = 16)
        {
            if (length < 8 || length > 64)
            {
                throw new ArgumentException("Password length must be between 8 and 64 characters.");
            }

            const string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowerChars = "abcdefghijklmnopqrstuvwxyz";
            const string digitChars = "0123456789";
            const string specialChars = "!@#$%^&*()-_=+[]{}|;:',.<>?";

            // Ensure at least one character from each category
            char[] password = new char[length];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            password[0] = GetRandomCharacter(upperChars, rng);
            password[1] = GetRandomCharacter(lowerChars, rng);
            password[2] = GetRandomCharacter(digitChars, rng);
            password[3] = GetRandomCharacter(specialChars, rng);

            // Fill the remaining characters randomly from all categories
            string allChars = upperChars + lowerChars + digitChars + specialChars;
            for (int i = 4; i < length; i++)
            {
                password[i] = GetRandomCharacter(allChars, rng);
            }

            // Shuffle the password to randomize character order
            ShuffleArray(password, rng);

            return new Password(new string(password));
        }

        private static char GetRandomCharacter(string characterSet, RandomNumberGenerator rng)
        {
            byte[] randomBytes = new byte[1];
            rng.GetBytes(randomBytes);
            int index = randomBytes[0] % characterSet.Length;
            return characterSet[index];
        }

        private static void ShuffleArray(char[] array, RandomNumberGenerator rng)
        {
            for (int i = array.Length - 1; i > 0; i--)
            {
                byte[] randomBytes = new byte[1];
                rng.GetBytes(randomBytes);
                int j = randomBytes[0] % (i + 1);

                // Swap elements
                char temp = array[i];
                array[i] = array[j];
                array[j] = temp;
            }
        }
    }
}
