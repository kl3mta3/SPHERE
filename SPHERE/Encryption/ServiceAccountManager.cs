using System;
using System.Runtime.InteropServices;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SPHERE;
using System.Security.Cryptography;

namespace SPHERE.Configure
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
        internal static string ServiceAccountName = AppIdentifier.GetOrCreateAppIdentifier();

        public static void ServiceAccountLogon()   // Starts or creats the Service Account
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
                        var newPass= Guid.NewGuid().ToString();
                        using (var newUser = new UserPrincipal(context))
                        {
                            newUser.SamAccountName = AppIdentifier.GetOrCreateAppIdentifier();
                            newUser.SetPassword(newPass);
                            newUser.PasswordNeverExpires = true;
                            newUser.UserCannotChangePassword = false;
                            newUser.Save();
                            AccountRestrictionManager.RestrictLogonRights(newUser.SamAccountName);

                            Console.WriteLine($"Service account '{newUser.SamAccountName}' created successfully.");
                        }
                    }
                    else
                    {
                        //Get username and password as account exists
                        var (username, password) = CredentialManager.GetOrCreateCredentials(AppIdentifier.GetOrCreateAppIdentifier());
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
                    if (LogonUser(username, ".", password, 2, 0, out userToken)) // LOGON32_LOGON_INTERACTIVE
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
                    if (!CredentialManager.VerifyCurrentPassword(AppIdentifier.GetOrCreateAppIdentifier(), currentPassword))
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

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword,
            int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

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

    public class AppIdentifier
        {
            private const string RegistryKeyPath = @"HKEY_CURRENT_USER\Software\SPHERE";
            private const string RegistryValueName = "SPHERE";

            // Returns the unique application identifier.
            public static string GetOrCreateAppIdentifier()
            {
                // Try to get the existing identifier from the registry
                string appIdentifier = (string)Registry.GetValue(RegistryKeyPath, RegistryValueName, null);

                // If it doesn't exist, create and store a new one
                if (string.IsNullOrEmpty(appIdentifier))
                {
                    appIdentifier = Guid.NewGuid().ToString(); // Generate a new unique identifier
                    Registry.SetValue(RegistryKeyPath, RegistryValueName, appIdentifier);
                }

                return appIdentifier;
            }
        }
}