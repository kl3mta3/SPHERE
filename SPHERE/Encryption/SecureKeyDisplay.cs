using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Configure
{
    public class SecureKeyDisplay
    {
        // Import the MessageBox function from user32.dll
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int MessageBox(IntPtr hWnd, String lpText, String lpCaption, uint uType);

        // Display the private key securely
        public static void ShowPrivateKeySecurely(string privateKey)
        {
            if (string.IsNullOrWhiteSpace(privateKey))
            {
                Console.WriteLine("Private key is empty or null.");
                return;
            }

            // Show the private key in a Windows message box
            MessageBox(IntPtr.Zero, privateKey, "Secure Private Key Viewer", 0x00000001 | 0x00000040);

            // Explanation of flags:
            // 0x00000001 - OK button
            // 0x00000040 - Information icon
        }

        public static void ShowPrivateKeySecureWindow(string keyName)
        {
            // Authenticate the user before proceeding
            if (!ServiceAccountManager.AuthenticateUser())
            {
                Console.WriteLine("Authentication failed. Access denied.");
                return;
            }

            try
            {
                // Retrieve the private key securely
                RSAParameters privateKey = ServiceAccountManager.RetrievePrivateKeySecurely(keyName);

                // Convert the private key to a displayable format
                string privateKeyString = Convert.ToBase64String(privateKey.D);

                // Show the private key securely using a native Windows dialog
                SecureKeyDisplay.ShowPrivateKeySecurely(privateKeyString);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error displaying private key: {ex.Message}");
            }
        }
    }
}
