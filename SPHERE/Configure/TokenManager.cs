using SPHERE.Networking;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using SPHERE.Blockchain;

namespace SPHERE.Configure
{
    public class TokenManager
    {

        internal ConcurrentDictionary <string, PushToken> PushTokenBalance = new();
        public ConcurrentDictionary<string, PushToken> IssuedPushTokens = new();
        public ConcurrentDictionary<DateTime, PushToken> TokensPendingRemoval = new();
        private readonly object _lock = new();
        private readonly DateTime _timeLastTokenEarnedOverTime = new();

        public class PushToken
        {
            public string TokenId { get; set; } // Unique identifier for the token
            public string IssuerId { get; set; }   // The peer that issued this token
            public string ReceiverId { get; set; } // The node that earned the token
            public DateTime Timestamp { get; set; }   
            public string Signature { get; set; }
        }

        public static async Task StartEarnTokenOverTime()
        {
            // Check if the node has earned a token in the last 24 hours

            while (true)
            {
                try
                {
                    DateTime now = DateTime.UtcNow;


                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: There was an error earning the token over time {ex.Message}");
                }
            }
        }

        public static string SignPushToken(PushToken token, byte[] privateKey)
        {
            string data = $"{token.IssuerId}|{token.ReceiverId}|{token.Timestamp:o}";

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportPkcs8PrivateKey(privateKey, out _);
                byte[] signatureBytes = ecdsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256);
                return Convert.ToBase64String(signatureBytes);
            }
        }

        public static bool VerifyReceivedPushToken(Node node, PushToken token, byte[] publicKey)
        {
            if (node.Peer.NodeId == token.ReceiverId || node.Peer.NodeId != token.IssuerId)
            {
                return false;
            }

            string data = $"{token.IssuerId}|{token.ReceiverId}|{token.Timestamp:o}";

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                byte[] signatureBytes = Convert.FromBase64String(token.Signature);
                return ecdsa.VerifyData(Encoding.UTF8.GetBytes(data), signatureBytes, HashAlgorithmName.SHA256);
            }
        }

        public static bool VerifyIssuedPushToken(Node node, PushToken token, byte[] publicKey)
        {
            if (node.Peer.NodeId != token.ReceiverId || node.Peer.NodeId == token.IssuerId)
            {
                return false;
            }

            string data = $"{token.IssuerId}|{token.ReceiverId}|{token.Timestamp:o}";

            using (var ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                byte[] signatureBytes = Convert.FromBase64String(token.Signature);
                return ecdsa.VerifyData(Encoding.UTF8.GetBytes(data), signatureBytes, HashAlgorithmName.SHA256);
            }
        }

        // Generates a Unique ID for the token using ECC signature
        public static string GenerateTokenId(string issuer, string receiver, DateTime timestamp)
        {
            string rawData = $"{issuer}|{receiver}|{timestamp:o}";
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                return Convert.ToBase64String(hash);
            }
        }

        //adds a token to the balance

        public async Task AddReceivedPushToken(Node node, PushToken token, byte[] publicKey)
        {
            try
            {
                lock (_lock)
                {
                    if (VerifyReceivedPushToken(node, token, publicKey))
                    {
                        PushTokenBalance.TryAdd(token.TokenId, token);
                    }
                    else
                    {
                        Console.WriteLine("Error: The token is not valid"); 
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: There was an error adding the earned Push Token {ex.Message}");
            }
        }




        public async Task AddIssuedPushToken(PushToken token )
        {
            try
            {
                lock (_lock)
                {

                        IssuedPushTokens.TryAdd(token.TokenId, token);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: There was an error adding the earned Push Token {ex.Message}");
            }
        }

        //spends a token from the balance
        public PushToken SpendPushToken(Node node, PushToken token, byte[] publicKey)
        {
            lock (_lock)
            {
                if (VerifyReceivedPushToken(node, token, publicKey))
                {
                    if (PushTokenBalance.TryRemove(token.TokenId, out _))
                    {
                        return token;
                    }
                }

                return null;
            }
        }

        //gets the number of tokens in the balance
        public int GetTokenBalance()
        {
            lock (_lock)
            {
                return PushTokenBalance.Count;
            }
        }


        //cash out an Issued token
        public async Task<bool> CashOutIssuedToken(Node node, PushToken token, byte[] publicKey)
        {
            lock (_lock)
            {
                if (!VerifyIssuedPushToken(node, token, publicKey))
                {
                    Console.WriteLine("Error: The token is not valid");
                    return false;
                }

                if (PushTokenBalance.TryRemove(token.TokenId, out _))
                {
                    Console.WriteLine($"Debug-CashOutToken: Spent token {token.TokenId} from {token.IssuerId}");
                    return true;
                }
                else
                {
                    Console.WriteLine("Error: The token is not in the balance");
                    return false;
                }

            }
        }

        //clears the token balance
        public void ClearTokenBalance()
        {

            lock (_lock)
            {
                PushTokenBalance.Clear();
            }

        }
       
    }
}
