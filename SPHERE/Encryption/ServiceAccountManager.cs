using System;
using System.Runtime.InteropServices;
using System.DirectoryServices.AccountManagement;
using System.Net;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using SPHERE;

namespace SPHERE
{ 
    public static class ServiceAccountManager
    {
        internal static string ServiceAccountName = AppIdentifier.GetOrCreateAppIdentifier();

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

        public static void ChangeServiceAccountPassword(string accountName, string newPassword)
            {
                try
                {
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
    }

    public static class CredentialManager
    {
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool CredWrite(ref Credential userCredential, uint flags);
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);
            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool CredDelete(string target, uint type, uint flags);
            [DllImport("advapi32.dll", SetLastError = true)]

            private static extern void CredFree(IntPtr credentialPtr);
            private const uint CRED_TYPE_GENERIC = 1;

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct Credential
            {
                public uint Flags;
                public uint Type;
                public string TargetName;
                public string Comment;
                public IntPtr CredentialBlob;
                public IntPtr CredentialBlobLast;
                public IntPtr CredentialBlobLastTwo;
                public IntPtr CredentialBlobLastThree;
                public IntPtr CredentialBlobLastFour;
                public IntPtr CredentialBlobLastFive;
                public uint CredentialBlobSize;
                public uint CredentialBlobLastSize;
                public uint CredentialBlobLastTwoSize;
                public uint CredentialBlobLastThreeSize;
                public uint CredentialBlobLastFourSize;
                public uint CredentialBlobLastFiveSize;
                public uint Persist;
                public uint AttributeCount;
                public IntPtr Attributes;
                public string TargetAlias;
                public string UserName;
            }

            public static (string Username, string[] Password) GetOrCreateCredentials(string target)
            {
                var username = "";
                string[] password = new string[6];
                if (CredentialManager.CredentialExists(target))
                {
                    var (Username, Password)=CredentialManager.GetCredential(target);

                    username = Username;
                    password = Password;
                    return (username, password);
                }
                else
                {
                    username = Guid.NewGuid().ToString();
                    var _password = Guid.NewGuid().ToString();
                    for (int i = 0; i < 5; i++)
                    {
                        password[i] = _password.ToString();

                    }
                    SaveCredential(AppIdentifier.GetOrCreateAppIdentifier(), username, password);

                    return (username, password);
                }


            }

            public static void SaveCredential(string target, string username, string[] password)
            {
               
                var credentialBlob = Encoding.Unicode.GetBytes(password[0]);
                var credentialBloblast = Encoding.Unicode.GetBytes(password[1]);
                var credentialBloblastTwo = Encoding.Unicode.GetBytes(password[2]);
                var credentialBloblastThree = Encoding.Unicode.GetBytes(password[3]);
                var credentialBloblastFour = Encoding.Unicode.GetBytes(password[4]);
                var credentialBloblastFive = Encoding.Unicode.GetBytes(password[5]);

                var credential = new Credential
                {
                    Type = CRED_TYPE_GENERIC,
                    TargetName = target,
                    UserName = username,
                    CredentialBlob = Marshal.AllocHGlobal(credentialBlob.Length),
                    CredentialBlobLast = Marshal.AllocHGlobal(credentialBloblast.Length),
                    CredentialBlobLastTwo = Marshal.AllocHGlobal(credentialBloblastTwo.Length),
                    CredentialBlobLastThree = Marshal.AllocHGlobal(credentialBloblastThree.Length),
                    CredentialBlobLastFour = Marshal.AllocHGlobal(credentialBloblastFour.Length),
                    CredentialBlobLastFive = Marshal.AllocHGlobal(credentialBloblastFive.Length),
                    CredentialBlobSize = (uint)credentialBlob.Length,
                    CredentialBlobLastSize = (uint)credentialBloblast.Length,
                    CredentialBlobLastTwoSize = (uint)credentialBloblastTwo.Length,
                    CredentialBlobLastThreeSize = (uint)credentialBloblastThree.Length,
                    CredentialBlobLastFourSize = (uint)credentialBloblastFour.Length,
                    CredentialBlobLastFiveSize = (uint)credentialBloblastFive.Length,
                    Persist = 2, // CRED_PERSIST_LOCAL_MACHINE
                    AttributeCount = 0,
                    Attributes = IntPtr.Zero,
                    TargetAlias = null,
                    Comment = "Service account credentials"
                };

                try
                {
                    Marshal.Copy(credentialBlob, 0, credential.CredentialBlob, credentialBlob.Length);

                    if (!CredWrite(ref credential, 0))
                    {
                        throw new InvalidOperationException($"Failed to save credential. Error: {Marshal.GetLastWin32Error()}");
                    }

                    Console.WriteLine($"Credential for '{target}' saved successfully.");
                }
                finally
                {
                    Marshal.FreeHGlobal(credential.CredentialBlob);
                    Marshal.FreeHGlobal(credential.CredentialBlobLast);
                    Marshal.FreeHGlobal(credential.CredentialBlobLastTwo);
                    Marshal.FreeHGlobal(credential.CredentialBlobLastThree);
                    Marshal.FreeHGlobal(credential.CredentialBlobLastFour);
                    Marshal.FreeHGlobal(credential.CredentialBlobLastFive);
                }
            }

            public static void CycleAndUpdateCredentialPassword(string target)
            {
                IntPtr currentBlob = IntPtr.Zero;
                IntPtr lastBlob = IntPtr.Zero;
                IntPtr lastBlobTwo = IntPtr.Zero;
                IntPtr lastBlobThree = IntPtr.Zero;
                IntPtr lastBlobFour = IntPtr.Zero;
                IntPtr lastBlobFive = IntPtr.Zero;
                string username = "";

                try
                {
                    // Retrieve existing credential if it exists
                    if (CredRead(target, CRED_TYPE_GENERIC, 0, out IntPtr credentialPtr))
                    {
                        var existingCredential = (Credential)Marshal.PtrToStructure(credentialPtr, typeof(Credential));

                        // Preserve current and historical blobs
                        currentBlob = existingCredential.CredentialBlob;
                        lastBlob = existingCredential.CredentialBlobLast;
                        lastBlobTwo = existingCredential.CredentialBlobLastTwo;
                        lastBlobThree = existingCredential.CredentialBlobLastThree;
                        lastBlobFour = existingCredential.CredentialBlobLastFour;
                        lastBlobFive = existingCredential.CredentialBlobLastFive;
                        username = existingCredential.UserName;

                        CredFree(credentialPtr);
                    }

                    // Generate a new password
                    var newPassword = Guid.NewGuid().ToString();

                    // Change the password on the service account
                    ServiceAccountManager.ChangeServiceAccountPassword(username, newPassword);

                    // Encrypt the password before adding to Credential
                    byte[] newPasswordBytes = Encoding.Unicode.GetBytes(newPassword);

                    // Allocate memory for the new password and history
                    var credential = new Credential
                    {
                        Type = CRED_TYPE_GENERIC,
                        TargetName = target,
                        UserName = username,
                        CredentialBlob = Marshal.AllocHGlobal(newPasswordBytes.Length),
                        CredentialBlobLast = currentBlob,
                        CredentialBlobLastTwo = lastBlob,
                        CredentialBlobLastThree = lastBlobTwo,
                        CredentialBlobLastFour = lastBlobThree,
                        CredentialBlobLastFive = lastBlobFour,
                        CredentialBlobSize = (uint)newPasswordBytes.Length,
                        CredentialBlobLastSize = currentBlob != IntPtr.Zero ? (uint)newPasswordBytes.Length : 0,
                        CredentialBlobLastTwoSize = lastBlob != IntPtr.Zero ? (uint)newPasswordBytes.Length : 0,
                        CredentialBlobLastThreeSize = lastBlobTwo != IntPtr.Zero ? (uint)newPasswordBytes.Length : 0,
                        CredentialBlobLastFourSize = lastBlobThree != IntPtr.Zero ? (uint)newPasswordBytes.Length : 0,
                        CredentialBlobLastFiveSize = lastBlobFour != IntPtr.Zero ? (uint)newPasswordBytes.Length : 0,
                        Persist = 2, // CRED_PERSIST_LOCAL_MACHINE
                        AttributeCount = 0,
                        Attributes = IntPtr.Zero,
                        TargetAlias = null,
                        Comment = "Updated by application with password history"
                    };

                    // Copy new password into CredentialBlob
                    Marshal.Copy(newPasswordBytes, 0, credential.CredentialBlob, newPasswordBytes.Length);

                    // Save the updated credential
                    if (!CredWrite(ref credential, 0))
                    {
                        throw new InvalidOperationException($"Failed to update credential. Error: {Marshal.GetLastWin32Error()}");
                    }

                    Console.WriteLine($"Credential for '{target}' updated successfully with password history.");
                }
                finally
                {
                    // Free memory for the oldest blob
                    if (lastBlobFive != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(lastBlobFive);
                    }
                }
            }

            public static (string Username, string[] Passwords) GetCredential(string target)
            {
                if (!CredRead(target, CRED_TYPE_GENERIC, 0, out IntPtr credentialPtr))
                {
                    throw new InvalidOperationException($"Failed to retrieve credential. Error: {Marshal.GetLastWin32Error()}");
                }

                try
                {
                    var credential = (Credential)Marshal.PtrToStructure(credentialPtr, typeof(Credential));
                    string[] passwords = new string[6];

                    // Retrieve the current password
                    if (credential.CredentialBlob != IntPtr.Zero && credential.CredentialBlobSize > 0)
                    {
                        passwords[0] = Marshal.PtrToStringUni(credential.CredentialBlob, (int)(credential.CredentialBlobSize / 2));
                    }

                    // Retrieve historical passwords
                    passwords[1] = credential.CredentialBlobLast != IntPtr.Zero && credential.CredentialBlobLastSize > 0
                        ? Marshal.PtrToStringUni(credential.CredentialBlobLast, (int)(credential.CredentialBlobLastSize / 2))
                        : null;

                    passwords[2] = credential.CredentialBlobLastTwo != IntPtr.Zero && credential.CredentialBlobLastTwoSize > 0
                        ? Marshal.PtrToStringUni(credential.CredentialBlobLastTwo, (int)(credential.CredentialBlobLastTwoSize / 2))
                        : null;

                    passwords[3] = credential.CredentialBlobLastThree != IntPtr.Zero && credential.CredentialBlobLastThreeSize > 0
                        ? Marshal.PtrToStringUni(credential.CredentialBlobLastThree, (int)(credential.CredentialBlobLastThreeSize / 2))
                        : null;

                    passwords[4] = credential.CredentialBlobLastFour != IntPtr.Zero && credential.CredentialBlobLastFourSize > 0
                        ? Marshal.PtrToStringUni(credential.CredentialBlobLastFour, (int)(credential.CredentialBlobLastFourSize / 2))
                        : null;

                    passwords[5] = credential.CredentialBlobLastFive != IntPtr.Zero && credential.CredentialBlobLastFiveSize > 0
                        ? Marshal.PtrToStringUni(credential.CredentialBlobLastFive, (int)(credential.CredentialBlobLastFiveSize / 2))
                        : null;

                    return (credential.UserName, passwords);
                }
                finally
                {
                    CredFree(credentialPtr);
                }
            }

            public static bool CredentialExists(string target)
            {
                IntPtr credentialPtr = IntPtr.Zero;
                try
                {
                    // Check if the credential exists
                    return CredRead(target, CRED_TYPE_GENERIC, 0, out credentialPtr);
                }
                finally
                {
                    if (credentialPtr != IntPtr.Zero)
                    {
                        CredFree(credentialPtr);
                    }
                }
            }

            public static void DeleteCredential(string target)
            {
                if (!CredDelete(target, CRED_TYPE_GENERIC, 0))
                {
                    throw new InvalidOperationException($"Failed to delete credential. Error: {Marshal.GetLastWin32Error()}");
                }

                Console.WriteLine($"Credential for '{target}' deleted successfully.");
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