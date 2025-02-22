// Ignore Spelling: App

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace SPHERE.Security
{
    internal class AppIdentifier
    {
        private const string RegistryKeyPath = @"HKEY_CURRENT_USER\Software\SPHERE";
        private const string RegistryValueID = "Appid";
        private const string RegistryValueServiceName = "ServiceName";
        private const string RegistryValueNodeID = "NodeID";


        // Returns the unique application identifier.
        internal static string GetOrCreateAppId()
        {
            // Try to get the existing identifier from the registry
            string appIdentifier = (string)Registry.GetValue(RegistryKeyPath, RegistryValueID, null);

            // If it doesn't exist, create and store a new one
            if (string.IsNullOrEmpty(appIdentifier))
            {
                appIdentifier = Guid.NewGuid().ToString(); // Generate a new unique identifier
                Registry.SetValue(RegistryKeyPath, RegistryValueID, appIdentifier);
            }

            return appIdentifier;
        }

        // Returns the unique ServiceName.
        internal static string GetOrCreateServiceName()
        {
            // Try to get the existing service account name from the registry
            string serviceAccountName = (string)Registry.GetValue(RegistryKeyPath, RegistryValueServiceName, null);

            // If it doesn't exist, create and store a new one
            if (string.IsNullOrEmpty(serviceAccountName))
            {
                serviceAccountName = GenerateRandomServiceName(15); // Generate a 15-character name
                Registry.SetValue(RegistryKeyPath, RegistryValueServiceName, serviceAccountName);
            }

            return serviceAccountName;
        }

        //Generates a unique Service Name.
        private static string GenerateRandomServiceName(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            char[] result = new char[length];

            for (int i = 0; i < length; i++)
            {
                result[i] = chars[random.Next(chars.Length)];
            }

            return new string(result);
        }

        // Returns the unique 256-bit DHT node ID.
        internal static string GetOrCreateDHTNodeID()
        {
            // Try to get the existing DHT node ID from the registry
            string dhtNodeID = (string)Registry.GetValue(RegistryKeyPath, RegistryValueNodeID, null);

            // If it doesn't exist, create and store a new one
            if (string.IsNullOrEmpty(dhtNodeID))
            {
                dhtNodeID = Generate256BitID(); // Generate a new 256-bit ID
                Registry.SetValue(RegistryKeyPath, RegistryValueNodeID, dhtNodeID);
            }

            return dhtNodeID;
        }

        // Generates a 256-bit (64-character hex) unique ID
        private static string Generate256BitID()
        {
            using (var sha256 = SHA256.Create())
            {
                // Use a GUID as the seed for hashing
                string guid = Guid.NewGuid().ToString();
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(guid));

                // Convert the hash to a 64-character hexadecimal string
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

    }
}
