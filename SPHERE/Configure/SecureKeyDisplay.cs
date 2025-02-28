using System.Runtime.InteropServices;
using SPHERE.Security;
using SPHERE.Configure.Logging;
using SPHERE.Blockchain;
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
                SystemLogger.Log("Private key is empty or null.");
                return;
            }

            // Show the private key in a Windows message box
            MessageBox(IntPtr.Zero, privateKey, "Secure Private Key Viewer", 0x00000001 | 0x00000040);

   
        }

        public static void ShowPrivateKeySecureWindow(Node node, KeyGenerator.KeyType keyType, Password password)
        {
            
            try
            {
                //Verify Inputs
                if (string.IsNullOrWhiteSpace(password.Value))
                {
                    throw new ArgumentNullException(nameof(password),"Password can not be null");
                }


                // Retrieve the private key securely, validating with the password if necessary
                string privateKeyString = Convert.ToBase64String(node.KeyManager.UseKeyInStorageContainer(node, keyType));

                // Show the private key securely using a native Windows dialog
                SecureKeyDisplay.ShowPrivateKeySecurely(privateKeyString);
            }
            catch (UnauthorizedAccessException ex)
            {
                SystemLogger.Log($"Access denied: {ex.Message}");
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error displaying private key: {ex.Message}");
            }
        }
    }
}
