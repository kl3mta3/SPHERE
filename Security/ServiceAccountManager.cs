using System.Runtime.InteropServices;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.Runtime.ConstrainedExecution;


namespace SPHERE.Security
{
    /// <summary>
    /// The Local Service Account(LSA) is used to allow for storing the Encryption keys and important data in CNG Containers that are bound to the specific service account. 
    /// 
    /// Traditional CNG containers are bound to the user of the computer. This secures them behind their log in, but the containers would be open to anyother app on the users account. 
    /// (they coudnt be accessed for copy if export is turned off) however, a malicious app could gain access and sign an malicious block edit or add. By restricting the containers to 
    /// a service account and then restricting that access to the app alone, we reduce the attack surface drasticlly. 
    /// 
    /// The LSA is created using a dynamic username and password.  Passwords are changed every time it is accessed. (which is at log on or creation most likely, or password resets)
    /// 
    /// Developers will only need to use ServiceAccountLogon()  it will check if an accout exists and create one if it doesnt. 
    /// The service account name is created and stored in the registry while the account name and passoword are managed by the Credential Manager to rotate passwords and keep them in sync. 
    /// 
    /// The Service Account Provides access to the Keys stored locally in a manner that allows them to never be exposed. 
    /// Because the Service account is more secure export of containers can be allowed, IN RARE HIGHLY CONTROLED SITUATIONS, FOR BACK UP. (Not Yet Implemented.) It would be best before this to implament Dynamic Container Names.
    /// 
    /// If access to this account is lost, the CNG Containers, and thus the keys are locked away inaccessable. Though you would still have the semi private key and BlockId for the contact so you could share and see it,  Editing it, or proving ownership would be impossible. 
    /// 
    /// </summary>
    public static class ServiceAccountManager
    {

        internal static string ServiceAccountName = AppIdentifier.GetOrCreateServiceName();


        // Starts or creats the Service Account
        public static void ServiceAccountLogon()
        {
            try
            {
              

                using (var context = new PrincipalContext(ContextType.Machine))
                {
                    // Check if the service account exists
                    UserPrincipal user = UserPrincipal.FindByIdentity(context, ServiceAccountName);

                    if (user == null)
                    {
                        // Create the service account
                        Console.WriteLine("Service account does not exist. Creating...");
                        var newPass = Guid.NewGuid().ToString();
                        using (var newUser = new UserPrincipal(context))
                        {
                            newUser.SamAccountName = AppIdentifier.GetOrCreateServiceName();
                            newUser.SetPassword(newPass);
                            newUser.PasswordNeverExpires = true;
                            newUser.UserCannotChangePassword = false;
                            newUser.Enabled = true;
                            newUser.Save();
                            AccountRestrictionManager.RestrictLogonRights(newUser.SamAccountName);

                            Console.WriteLine($"Service account '{newUser.SamAccountName}' created successfully.");
                        }
                    }
                    else
                    {
                        //Get username and password as account exists
                        var (username, password) = CredentialManager.GetOrCreateCredentials(AppIdentifier.GetOrCreateAppId());
                        // Log into the service account
                        AuthenticateServiceAccount(username, password);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error ensuring service account existence: {ex.Message}");
                throw;
            }
        }

        private static void AuthenticateServiceAccount(string username, string[] passwordList)
        {
            IntPtr userToken = IntPtr.Zero;

            foreach (string password in passwordList)
            {
                try
                {
                    // Attempt to log in with the current password
                    if (LogonUser(username, ".", password, 5, 0, out userToken)) // LOGON32_LOGON_SERVICE
                    {
                        // Use the token with impersonation
                        WindowsIdentity.RunImpersonated(new SafeAccessTokenHandle(userToken), () =>
                        {
                            Console.WriteLine($"Successfully authenticated and impersonated service account '{username}' with the provided password.");
                            // Perform actions as the impersonated user here
                        });

                        return; // Exit if authentication succeeds
                    }
                    else
                    {
                        Console.WriteLine($"Authentication failed for service account '{username}' with the current password. Trying next...");
                    }
                }
                finally
                {
                    if (userToken != IntPtr.Zero)
                    {
                        CloseHandle(userToken); // Always release the token
                        userToken = IntPtr.Zero; // Reset for the next iteration
                    }
                }
            }

            // If all passwords fail

            throw new InvalidOperationException($"Failed to authenticate service account '{username}' with all provided passwords.");
        }

        public static void ChangeServiceAccountPassword(string accountName, string newPassword, string currentPassword) //used to change the service account password.
        {
            try
            {
                if (!CredentialManager.VerifyCurrentPassword(AppIdentifier.GetOrCreateAppId(), currentPassword))
                {
                    throw new InvalidOperationException($"Failed to verify current credential.");

                }
                using (var context = new PrincipalContext(ContextType.Machine))
                {
                    // Find the service account
                    UserPrincipal user = UserPrincipal.FindByIdentity(context, accountName);

                    if (user == null)
                    {
                        throw new InvalidOperationException($"Service account '{accountName}' does not exist.");
                    }

                    // Change the password

                    user.SetPassword(newPassword);

                    user.Save();

                    Console.WriteLine($"Password for service account '{accountName}' successfully updated.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error updating password for service account '{accountName}': {ex.Message}");
                throw;
            }
        }

        // The Encryption Keys are stored in Local CNG Containers.  Those containers are only accessable by the local Service account the App Creates and runs on. NO EXPORT Safest option for private keys.
        public static void StoreKeyInContainerWithoutExport(byte[] key, KeyGenerator.KeyType keyType)
        {
            string keyName = keyType.ToString();
            string AppId = AppIdentifier.GetOrCreateAppId();

            // Ensure the service account exists
            using (var context = new PrincipalContext(ContextType.Machine))
            {
                // Check if the service account exists
                UserPrincipal user = UserPrincipal.FindByIdentity(context, ServiceAccountName);

                if (user == null)
                {
                    ServiceAccountManager.ServiceAccountLogon();
                }
            }

            try
            {
                // Convert the key from Base64
                byte[] convertedKey = key;

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

        /// <summary>
        /// The Encryption PrivateKeys are stored in Local CNG Containers.  Those containers are only accessable by the local Service account the App Creates and runs on. EXPORT AS PLAIN TEXT !!!! DANGEROUS BUT NECESSARY SOMETIMES.  Only Viewable as EXPORTABLE TO A DIALOG BOX NO DEV ACCESS OTHERWISE!
        /// This is necessary for export as for users to migrate from one "Node" or app to another these keys would be needed as they are the users identity in the chain. If fully lost or locked away so is access to edit or share the block. the user will need to start over. 
        /// <param name="key"></param>
        /// <param name="keyName"></param>
        /// <param name="password"></param>
        /// <exception cref="ArgumentException"></exception>
        /// </summary>
        public static void StorePrivateKeyInContainerWithExportPlainText(byte[] key, KeyGenerator.KeyType keyType, Password password)
        {
            if (keyType == null || keyType == KeyGenerator.KeyType.PublicNodeEncryptionKey || keyType == KeyGenerator.KeyType.PublicNodeSignatureKey || keyType == KeyGenerator.KeyType.PublicPersonalEncryptionKey || keyType == KeyGenerator.KeyType.PublicPersonalSignatureKey)
            {
                throw new ArgumentNullException("A Private KeyType is needed.", nameof(keyType));
            }



            if (string.IsNullOrWhiteSpace(password.Value))
            {
                throw new ArgumentException("Password is required for storing private keys.", nameof(password));
            }

            string AppId = AppIdentifier.GetOrCreateAppId();
            string keyName = keyType.ToString();

            try
            {
                // Convert the key from Base64
                byte[] convertedKey = key;

                // Define key creation parameters
                var creationParameters = new CngKeyCreationParameters
                {
                    ExportPolicy = CngExportPolicies.None, // Private keys are not exportable by default
                    KeyUsage = CngKeyUsages.Signing | CngKeyUsages.Decryption
                };

                // Create the key
                using var cngKey = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParameters);

                // Store the application-specific identifier
                cngKey.SetProperty(new CngProperty("AppId", Encoding.UTF8.GetBytes(AppId), CngPropertyOptions.None));

                // Store the key data securely
                cngKey.SetProperty(new CngProperty("KeyData", convertedKey, CngPropertyOptions.None));

                // Generate the password hash
                byte[] salt = new byte[16];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                using (var deriveBytes = new Rfc2898DeriveBytes(password.Value, salt, 10000, HashAlgorithmName.SHA256))
                {
                    byte[] hash = deriveBytes.GetBytes(32);

                    // Combine the salt and hash for storage
                    byte[] hashWithSalt = new byte[salt.Length + hash.Length];
                    Array.Copy(salt, 0, hashWithSalt, 0, salt.Length);
                    Array.Copy(hash, 0, hashWithSalt, salt.Length, hash.Length);

                    // Store the password hash in the container
                    cngKey.SetProperty(new CngProperty("PasswordHash", hashWithSalt, CngPropertyOptions.None));
                }

                Console.WriteLine("Private key stored securely with password protection.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing private key: {ex.Message}");
                throw;
            }
        }

        // The Encryption PublicKeys are stored in Local CNG Containers.  Those containers are only accessable by the local Service account the App Creates and runs on. EXPORT AS PLAIN TEXT FOR PUBLIC KEYS HAS LITTLE RISK AND IS NEEDED OFTEN. 
        public static void StorePublicKeyInContainerWithExportPlainText(byte[] key, KeyGenerator.KeyType keyType)
        {
            string AppId = AppIdentifier.GetOrCreateAppId();
            string keyName = keyType.ToString();

            try
            {
                // Convert the key from Base64
                byte[] convertedKey = key;

                // Define key creation parameters
                var creationParameters = new CngKeyCreationParameters
                {
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport, // Public keys are exportable
                    KeyUsage = CngKeyUsages.KeyAgreement
                };

                // Create the key
                using var cngKey = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParameters);

                // Store the application-specific identifier
                cngKey.SetProperty(new CngProperty("AppId", Encoding.UTF8.GetBytes(AppId), CngPropertyOptions.None));

                // Store the key data securely
                cngKey.SetProperty(new CngProperty("KeyData", convertedKey, CngPropertyOptions.None));

                Console.WriteLine("Public key stored securely and is exportable.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing public key: {ex.Message}");
                throw;
            }
        }

        // The Encryption Keys are stored in Local CNG Containers.  Those containers are only accessable by the local Service account the App Creates and runs on. EXPORT AS CNGContainer.  MUCH SAFER OPTION BUT ONLY VIABLE TO OTHER WINDOWS DEVICES.
        public static void StoreKeyInContainerWithExport(byte[] key, KeyGenerator.KeyType keyType, string password = null, bool isPublicKey = false)
        {
            string AppId = AppIdentifier.GetOrCreateAppId();
            string keyName = keyType.ToString();
            try
            {
                // Convert the key from Base64
                byte[] convertedKey =key;

                // Define key creation parameters
                var creationParameters = new CngKeyCreationParameters
                {
                    ExportPolicy = isPublicKey ? CngExportPolicies.AllowExport : CngExportPolicies.None,
                    KeyUsage = isPublicKey ? CngKeyUsages.KeyAgreement : CngKeyUsages.Signing | CngKeyUsages.Decryption
                };

                // Create the key
                using var cngKey = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParameters);

                // Store the application-specific identifier
                cngKey.SetProperty(new CngProperty("AppId", Encoding.UTF8.GetBytes(AppId), CngPropertyOptions.None));

                // Store the key data securely
                cngKey.SetProperty(new CngProperty("KeyData", convertedKey, CngPropertyOptions.None));

                if (!isPublicKey && password != null)
                {
                    // Generate the password hash
                    byte[] salt = new byte[16];
                    using (var rng = RandomNumberGenerator.Create())
                    {
                        rng.GetBytes(salt);
                    }

                    using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
                    {
                        byte[] hash = deriveBytes.GetBytes(32);

                        // Combine the salt and hash for storage
                        byte[] hashWithSalt = new byte[salt.Length + hash.Length];
                        Array.Copy(salt, 0, hashWithSalt, 0, salt.Length);
                        Array.Copy(hash, 0, hashWithSalt, salt.Length, hash.Length);

                        // Store the password hash in the container
                        cngKey.SetProperty(new CngProperty("PasswordHash", hashWithSalt, CngPropertyOptions.None));
                    }
                }

                Console.WriteLine(isPublicKey
                    ? "Public key stored securely and is exportable."
                    : "Private key stored securely with password protection.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing key: {ex.Message}");
                throw;
            }
        }

        public static byte[] UseKeyInStorageContainer(KeyGenerator.KeyType keyType)
        {
            try
            {
                string testModeEnv = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE");
                Console.WriteLine($"SPHERE_TEST_MODE= {testModeEnv}.");
            }
            catch (Exception e)
            {
                throw new InvalidOperationException($" Test Environmental Var missing or not set.");
            }

            string keyName = keyType.ToString();
            Console.WriteLine($"Using Key From Storage {keyName}.");

            // Check existence using the correct provider
            if (!CngKey.Exists(keyName))
            {
                throw new InvalidOperationException($" Key '{keyName}' does not exist in CNG storage.");
            }

            try
            {
                // Detect if we're in a test environment
                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";

                // Choose the correct provider
                CngProvider provider = isTesting
                    ? CngProvider.MicrosoftSoftwareKeyStorageProvider  // ✅ Ensure same provider as creation
                    : CngProvider.MicrosoftSmartCardKeyStorageProvider; // ✅ Use per-user storage in production

                using var cngKey = CngKey.Open(keyName, provider); // Ensure it matches creation provider

                var format = keyType.ToString().Contains("Private")
                    ? CngKeyBlobFormat.Pkcs8PrivateBlob  // Ensure format matches creation
                    : CngKeyBlobFormat.EccPublicBlob;

                byte[] keyData = cngKey.Export(format);

                Console.WriteLine($"✅ Key '{keyName}' retrieved successfully from {(isTesting ? "TEST" : "PRODUCTION")} storage.");
                return keyData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error retrieving key '{keyName}': {ex.Message}");
                throw;
            }
        }

        public static string ExportPrivateKeyFromContainer(KeyGenerator.KeyType keyType, string password = null)
        {

            string keyName = keyType.ToString();
            try
            {
                // Open the key from the container
                using var cngKey = CngKey.Open(keyName);

                if (string.IsNullOrWhiteSpace(password))
                {
                    throw new UnauthorizedAccessException("Password is required to export the private key.");
                }

                // Retrieve and validate the password hash
                var passwordHashProperty = cngKey.GetProperty("PasswordHash", CngPropertyOptions.None);
                byte[] hashWithSalt = passwordHashProperty.GetValue();

                byte[] salt = new byte[16];
                byte[] storedHash = new byte[32];
                Array.Copy(hashWithSalt, 0, salt, 0, salt.Length);
                Array.Copy(hashWithSalt, salt.Length, storedHash, 0, storedHash.Length);

                using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
                {
                    byte[] computedHash = deriveBytes.GetBytes(32);

                    if (!computedHash.SequenceEqual(storedHash))
                    {
                        throw new UnauthorizedAccessException("Incorrect password.");
                    }
                }

                // Retrieve and validate the private key data
                var keyDataProperty = cngKey.GetProperty("KeyData", CngPropertyOptions.None);
                string privateKeyData = Convert.ToBase64String(keyDataProperty.GetValue());

                return privateKeyData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error exporting key: {ex.Message}");
                throw;
            }
        }

        public static string GenerateKademliaId()
        {
            byte[] randomBytes = new byte[32]; // 256 bits = 32 bytes
            using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
            {
                rng.GetBytes(randomBytes);
            }

            // Convert the random bytes to a 64-character hexadecimal string
            return BitConverter.ToString(randomBytes).Replace("-", "").ToLower();
        }

        public static string ExportPublicKeyFromContainer(KeyGenerator.KeyType keyType)
        {
            string keyName = keyType.ToString();
            try
            {
                // Open the key from the container
                using var cngKey = CngKey.Open(keyName);

                // Retrieve and validate the public key data
                var keyDataProperty = cngKey.GetProperty("KeyData", CngPropertyOptions.None);
                string publicKeyData = Convert.ToBase64String(keyDataProperty.GetValue());

                return publicKeyData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error exporting key: {ex.Message}");
                throw;
            }
        }

        public static bool KeyContainerExists(KeyGenerator.KeyType keyType)
        {
            string containerName = keyType.ToString();
            try
            {
                // Try to open the CNG key with the specified name
                using (CngKey.Open(containerName))
                {
                    // If successful, the container exists
                    return true;
                }
            }
            catch (CryptographicException)
            {
                // If an exception occurs, the container likely doesn't exist
                return false;
            }
        }

        public static RSAParameters RetrievePrivateKeySecurely(KeyGenerator.KeyType keyType)
        {
            string keyName = keyType.ToString();
            using (var rsa = new RSACryptoServiceProvider(new CspParameters
            {
                KeyContainerName = keyName,
                Flags = CspProviderFlags.UseMachineKeyStore
            }))
            {
                return rsa.ExportParameters(true); // Includes private key
            }
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }

    public static class AccountRestrictionManager
    {
        private const string DenyLogonLocallyRight = "SeDenyInteractiveLogonRight";
        private const string DenyLogonThroughRemoteDesktopRight = "SeDenyRemoteInteractiveLogonRight";

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int LsaAddAccountRights(IntPtr policyHandle, IntPtr accountSid, string[] userRights, int countOfRights);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int LsaOpenPolicy(ref LsaObjectAttributes objectAttributes, IntPtr objectName, int desiredAccess, out IntPtr policyHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int LsaClose(IntPtr policyHandle);

        public static void RestrictLogonRights(string accountName)
        {
            IntPtr policyHandle = IntPtr.Zero;
            IntPtr sidPointer = IntPtr.Zero;

            try
            {
                // Get the account SID
                var account = new NTAccount(accountName);
                var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));

                // Allocate memory for the SID as a byte array
                byte[] sidBinaryForm = new byte[sid.BinaryLength];
                sid.GetBinaryForm(sidBinaryForm, 0); // Retrieve the binary form of the SID

                // Allocate unmanaged memory and copy the SID binary form into it
                sidPointer = Marshal.AllocHGlobal(sidBinaryForm.Length);
                Marshal.Copy(sidBinaryForm, 0, sidPointer, sidBinaryForm.Length);

                // Open the policy
                var objectAttributes = new LsaObjectAttributes
                {
                    Length = Marshal.SizeOf(typeof(LsaObjectAttributes)),
                    RootDirectory = IntPtr.Zero,
                    ObjectName = IntPtr.Zero,
                    Attributes = 0,
                    SecurityDescriptor = IntPtr.Zero,
                    SecurityQualityOfService = IntPtr.Zero
                };
                int access = 0x00000800; // POLICY_WRITE

                var result = LsaOpenPolicy(ref objectAttributes, IntPtr.Zero, access, out policyHandle);
                if (result != 0)
                {
                    throw new InvalidOperationException($"Failed to open LSA Policy. Error code: {result}");
                }

                // Assign deny logon rights
                string[] rights = { DenyLogonLocallyRight, DenyLogonThroughRemoteDesktopRight };
                var status = LsaAddAccountRights(policyHandle, sidPointer, rights, rights.Length);

                if (status != 0) // LsaAddAccountRights returns NTSTATUS (0 is success)
                {
                    throw new InvalidOperationException($"Failed to assign logon rights to account: {accountName}. NTSTATUS: {status}");
                }

                Console.WriteLine($"Restricted logon rights for account: {accountName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error restricting logon rights: {ex.Message}");
            }
            finally
            {
                // Free the allocated memory
                if (sidPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(sidPointer);
                }

                // Close the policy handle
                if (policyHandle != IntPtr.Zero)
                {
                    LsaClose(policyHandle);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public int Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

    }
}
