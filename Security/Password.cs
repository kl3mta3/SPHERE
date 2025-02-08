using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Security
{
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
