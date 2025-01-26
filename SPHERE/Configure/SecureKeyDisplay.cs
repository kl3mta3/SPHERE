using System.Runtime.InteropServices;
using SPHERE.Security;

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

        public static void ShowPrivateKeySecureWindow(KeyGenerator.KeyType keyType, Password password)
        {
            
            try
            {
                //Verify Inputs
                if (string.IsNullOrWhiteSpace(password.Value))
                {
                    throw new ArgumentNullException(nameof(password),"Password can not be null");
                }

                if (keyType==null)
                {
                    throw new ArgumentNullException( "A Key Type is required.");

                }

                // Retrieve the private key securely, validating with the password if necessary
                string privateKeyString = ServiceAccountManager.ExportPrivateKeyFromContainer(keyType, password.Value);

                // Show the private key securely using a native Windows dialog
                SecureKeyDisplay.ShowPrivateKeySecurely(privateKeyString);
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"Access denied: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error displaying private key: {ex.Message}");
            }
        }
    }
}
