using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Security
{
    /// <summary>
    /// The Credential Manager is intended to Store and manage the Service Account Username and Password Dynamically.
    /// 
    /// The Password for the Service account is changed and cycled each time it is accessed. This reduces the attack window.
    /// Changing the password dynamically often has a small change of an out of sync issue where the cred will be updated but the password will not have updated.
    /// To counter this we store the current password and the last 5 used.  If we encounter a failed password, we check the most resent working backwards till we 
    /// find the last working password. Becase we used it, it will be reset resolving the out of sync issue.
    /// 
    /// Because the Service Account is used to store needed encryption keys in containers locked to the application as long as an attacker can not gain access to 
    /// the service account password, it will be very dificult to gain access to the private keys stored under the account in CNG Containers.
    /// 
    /// </summary>
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


        //Base structure of a Credential.
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

        //Returns the username and password [] containing the current and previous 5 passwords.
        public static (string Username, string[] Password) GetOrCreateCredentials(string target)
        {
            var username = "";
            string[] password = new string[6];
            if (CredentialManager.CredentialExists(target))
            {
                var (Username, Password) = CredentialManager.GetCredential(target);

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
                SaveCredential(AppIdentifier.GetOrCreateAppId(), username, password);

                return (username, password);
            }


        }

        //Saves a credential.  (Primarially used for the first set up of the service account and initial save of the Credentials.  For existing Credentials CycleandUpdate is prefered. As the Service Account relies on cycling passwords to maintain a smaller attack window ) 
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

        //Used To change the password for the service account upon use and update the credential cycling the passwords down.(We keep the last 5 incase there is an error in updating it and new is not added correctly we ensure we have the previous ones it would still be set to.)
        public static void CycleAndUpdateCredentialPassword(string target)
        {
            IntPtr currentBlob = IntPtr.Zero;
            IntPtr lastBlob = IntPtr.Zero;
            IntPtr lastBlobTwo = IntPtr.Zero;
            IntPtr lastBlobThree = IntPtr.Zero;
            IntPtr lastBlobFour = IntPtr.Zero;
            IntPtr lastBlobFive = IntPtr.Zero;
            uint credentialBlobLength = 0;
            string username = "";
            Credential existingCredential;

            try
            {
                // Retrieve existing credential if it exists
                if (CredRead(target, CRED_TYPE_GENERIC, 0, out IntPtr credentialPtr))
                {
                    existingCredential = (Credential)Marshal.PtrToStructure(credentialPtr, typeof(Credential));

                    // Preserve current and historical blobs
                    currentBlob = existingCredential.CredentialBlob;

                    lastBlob = existingCredential.CredentialBlobLast;
                    credentialBlobLength = existingCredential.CredentialBlobSize;
                    lastBlobTwo = existingCredential.CredentialBlobLastTwo;
                    lastBlobThree = existingCredential.CredentialBlobLastThree;
                    lastBlobFour = existingCredential.CredentialBlobLastFour;
                    lastBlobFive = existingCredential.CredentialBlobLastFive;
                    username = existingCredential.UserName;

                    CredFree(credentialPtr);
                }

                // Generate a new password
                var newPassword = Guid.NewGuid().ToString();

                // Change the password on the service account.  (requires the most recent current password.) 
                ServiceAccountManager.ChangeServiceAccountPassword(username, newPassword, Marshal.PtrToStringUni(currentBlob, (int)(credentialBlobLength / 2)));

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

        //User to get the Credentials for logging on to the serviceAccount. 
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

        //Checks to verify a Credential Exists
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

        //Used if a credential is needed to be deleted. 
        public static void DeleteCredential(string target)
        {
            if (!CredDelete(target, CRED_TYPE_GENERIC, 0))
            {
                throw new InvalidOperationException($"Failed to delete credential. Error: {Marshal.GetLastWin32Error()}");
            }

            Console.WriteLine($"Credential for '{target}' deleted successfully.");
        }

        //Used to verify the current service Account Password (Without revealing it)
        public static bool VerifyCurrentPassword(string target, string currnetPassword)
        {
            if (CredentialManager.CredentialExists(target))
            {
                var (Username, Password) = CredentialManager.GetCredential(target);
                var _currentPassword = Password[0];
                if (_currentPassword == currnetPassword)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {

                return false;
            }
        }
    }
}
