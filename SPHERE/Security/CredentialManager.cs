// Ignore Spelling: Hmac

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SPHERE.Configure.Logging;

namespace SPHERE.Security
{
    /// <summary>
    /// The Credential Manager is user to Assist a user in resetting their Credentials and assist with Verifying Log on.
    /// It is responsible for generating the Hashes of the Pass+ key and Pass+ Pin hashes needed to Gain assess along with the Key if a user 
    /// forgets their password or Pin.   The user can use the remaining known credential and the users PrivateKey(Provided when the account(Block) is first made. 
    /// </summary>
    internal static class CredentialManager
    {
      
        //Verify the provided Key and password match the stored string. 
        public static List<(byte[], byte[])> GenerateStoredHashes(byte[] fullKey, string password, string pin, string contactID)
        {
            List<(byte[], byte[])> storedHashes = new List<(byte[], byte[])>();

            // Generate real hashes with HMAC
            byte[] passHash = GenerateKeyPassHash(fullKey, password, contactID);
            byte[] pinHash = GenerateKeyPinHash(fullKey, pin, contactID);

            byte[] passHmac = GenerateHmac(passHash, fullKey);
            byte[] pinHmac = GenerateHmac(pinHash, fullKey);

            storedHashes.Add((passHash, passHmac));
            storedHashes.Add((pinHash, pinHmac));

            // Generate fake hashes (no valid HMAC)
            for (int i = 0; i < 3; i++)
            {
                byte[] fakeKey = RandomNumberGenerator.GetBytes(32);
                byte[] fakeSalt = SHA512.HashData(Encoding.UTF8.GetBytes(contactID + "FakeSalt" + i));

                // Corrected PBKDF2 implementation
                using var pbkdf2 = new Rfc2898DeriveBytes(fakeKey, fakeSalt, 100000, HashAlgorithmName.SHA256);
                byte[] fakeHash = pbkdf2.GetBytes(32); // Get a 32-byte hash

                // No HMAC for fake hashes
                storedHashes.Add((fakeHash, new byte[32]));
            }

            // Shuffle list
            storedHashes = storedHashes.OrderBy(x => RandomNumberGenerator.GetInt32(int.MaxValue)).ToList();

            return storedHashes;
        }

        public static byte[] GenerateKeyPassHash(byte[] fullKey, string password, string contactID)
        {
            byte[] salt = SHA512.HashData(Encoding.UTF8.GetBytes(contactID + "PassSalt"));
            using var pbkdf2 = new Rfc2898DeriveBytes(fullKey.Concat(Encoding.UTF8.GetBytes(password)).ToArray(), salt, 100000, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(64);
        }

        public static byte[] GenerateKeyPinHash(byte[] fullKey, string pin, string contactID)
        {
            byte[] salt = SHA512.HashData(Encoding.UTF8.GetBytes(contactID + "PinSalt"));
            using var pbkdf2 = new Rfc2898DeriveBytes(fullKey.Concat(Encoding.UTF8.GetBytes(pin)).ToArray(), salt, 100000, HashAlgorithmName.SHA512);
            return pbkdf2.GetBytes(64);
        }

        public static bool VerifyKeyForRecovery(byte[] providedKey, string input, List<(byte[], byte[])> storedHashes, string contactID, bool isPassword)
        {
            byte[] generatedHash = isPassword
                ? GenerateKeyPassHash(providedKey, input, contactID)
                : GenerateKeyPinHash(providedKey, input, contactID);

            byte[] expectedHmac = GenerateHmac(generatedHash, providedKey);

            // Look for a matching real hash with a valid HMAC
            foreach (var (storedHash, storedHmac) in storedHashes)
            {
                if (storedHash.SequenceEqual(generatedHash) && storedHmac.SequenceEqual(expectedHmac))
                {
                    return true; 
                }
            }

            return false; 
        }

        public static byte[] GenerateHmac(byte[] data, byte[] key)
        {
            using var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(data);
        }
    }
}
