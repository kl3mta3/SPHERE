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
using SPHERE.Configure.Logging;

namespace SPHERE.Configure
{
    /// <summary>
    /// This class is responsible for managing the tokens used for push notifications.
    /// More or less a Proof of Work system.
    /// </summary>
    public class TokenManager
    {

        internal ConcurrentDictionary<string, PushToken> PushTokenBalance = new();
        public ConcurrentDictionary<string, PushToken> IssuedPushTokens = new();
        public ConcurrentDictionary<DateTime, PushToken> TokensPendingRemoval = new();
        internal readonly object _lock = new();
        internal readonly DateTime _timeLastTokenEarnedOverTime = new();

        internal Peer pingPal = new Peer();
        internal Dictionary<Peer, DateTime> pingPals = new();

        // Parameters for dynamic cap and cleanup
        internal readonly int _baseCap = 5;                                 // Minimum tokens allowed
        internal readonly int _usageMultiplier = 1;                         // Each token spent in last 24 hours increases cap by this many
        internal readonly TimeSpan _staleThreshold = TimeSpan.FromDays(5);  // Tokens held longer than this are considered stale

        // A log to record when tokens are spent (used) for the last 24 hours
        internal readonly ConcurrentQueue<DateTime> _tokenUsageLog = new ConcurrentQueue<DateTime>();

        public class PushToken
        {
            public string TokenId { get; set; }                 // Unique identifier for the token
            public string IssuerId { get; set; }                // The peer that issued this token
            public string ReceiverId { get; set; }              // The node that earned the token
            public DateTime Timestamp { get; set; }
            public string Signature { get; set; }
        }

        public PushToken CreatePushToken(string issuerId, string receiverId)
        {
            PushToken token = new PushToken
            {
                IssuerId = issuerId,
                ReceiverId = receiverId,
                Timestamp = DateTime.UtcNow
            };

            token.TokenId = GenerateTokenId(token.IssuerId, token.ReceiverId, token.Timestamp);
            token.Signature = SignatureGenerator.SignPushToken(token);

            return token;
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
                    if (SignatureGenerator.VerifyReceivedPushToken(node, token, publicKey))
                    {
                        PushTokenBalance.TryAdd(token.TokenId, token);
                    }
                    else
                    {
                        SystemLogger.Log("Error: The token is not valid");
                    }
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error: There was an error adding the earned Push Token {ex.Message}");
            }
        }

        //cleans up the token balance
        public void CleanupTokenBalance()
        {
            lock (_lock)
            {
                // Remove usage events older than 24 hours from the log.
                DateTime cutoff = DateTime.UtcNow - TimeSpan.FromHours(24);
                while (_tokenUsageLog.TryPeek(out DateTime usageTime) && usageTime < cutoff)
                {
                    _tokenUsageLog.TryDequeue(out _);
                }

                int tokensUsedLast24 = _tokenUsageLog.Count;
                int maxAllowed = _baseCap + (_usageMultiplier * tokensUsedLast24);

                if (PushTokenBalance.Count > maxAllowed)
                {
                    // Order tokens by their issuance time (oldest first)
                    var tokensOrdered = PushTokenBalance.Values.OrderBy(t => t.Timestamp).ToList();

                    foreach (var token in tokensOrdered)
                    {
                        // If the token is "stale" (held longer than the stale threshold), remove it.
                        if (DateTime.UtcNow - token.Timestamp >= _staleThreshold)
                        {
                            PushTokenBalance.TryRemove(token.TokenId, out _);
                            SystemLogger.Log($"Removed stale token {token.TokenId} issued at {token.Timestamp}");
                            if (PushTokenBalance.Count <= maxAllowed)
                                break;
                        }
                    }
                }
            }
        }

        //Tracks Tokens that we issue to other nodes
        public async Task AddIssuedPushToken(PushToken token)
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
                    SystemLogger.Log($"Error: There was an error adding the earned Push Token {ex.Message}");
                }
            }

        //spends a token from the balance
        public PushToken SpendPushToken(Node node, byte[] publicKey, PushToken token)
            {
                lock (_lock)
                {
                    if (SignatureGenerator.VerifyReceivedPushToken(node, token, publicKey))
                    {
                        if (PushTokenBalance.TryRemove(token.TokenId, out _))
                        {
                            _tokenUsageLog.Enqueue(DateTime.UtcNow); //record we spent a token now
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
        public  Task CashOutIssuedToken(Node node, PushToken token)
        {
                lock (_lock)
                {
                    if (!SignatureGenerator.VerifyIssuedPushToken(node, token))
                    {
                        SystemLogger.Log("Error: The token is not valid");
                        return Task.CompletedTask;
                    }

                    if (PushTokenBalance.TryRemove(token.TokenId, out _))
                    {
                        SystemLogger.Log($"Debug-CashOutToken: Spent token {token.TokenId} from {token.IssuerId}");
                        return Task.CompletedTask;
                    }
                    else
                    {
                        SystemLogger.Log("Error: The token is not in the balance");
                        return Task.CompletedTask;
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


        //returns the oldest token from the balance
        public PushToken GetToken(string tokenId)
        {
            try
            {
                lock (_lock)
                {
                    if (GetTokenBalance() == 0 || string.IsNullOrWhiteSpace(tokenId))
                    {
                        return null;
                    }

                    PushToken tokens = PushTokenBalance.Values.OrderBy(t => t.Timestamp).FirstOrDefault();

                    if (tokens != null)
                    {
                        return tokens;
                    }
                    else
                    {
                        return null;
                    }
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error: There was an error getting the token {ex.Message}");
                return null;
            }
        }

    }
}

