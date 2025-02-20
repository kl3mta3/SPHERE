using SPHERE.Blockchain;
using SPHERE.Networking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SPHERE.Configure
{
    internal class CleanupTasks
    {
        /// <summary>
        /// We use an enum to define the cleanup tasks that can be run on startup, 
        /// a dictionary to map each enum value to a function that returns a Task,
        /// a dictionary to map cleanup task names to their intervals.
        /// This is so we can add new startup tasks easily and configure their intervals here and Loop through them in the ScheduledTaskManager.
        /// 
        /// This class contains the cleanup tasks that can be run on startup
        /// </summary>
        /// 
        // Enum of cleanup tasks that can be run on startup.
        public enum StartupTasks
        {
            AutoCleanupSeenPacketCache,
            AutoCleanupIssuedTokens,
            AutoCleanupTokensPendingRemoval,
            AutoEarnTokensOverTime,
            AutoBroadcastPeerPing,
            AutoPeriodicRebalance,
            AutoCleanUpPingPals,
            AutoCleanupTokenBalance


        }

        // Dictionary mapping each StartupTasks enum value to a function that returns a Task.
        public static Dictionary<StartupTasks, Func<CancellationToken, Task>> TaskMap { get; } =
            new Dictionary<StartupTasks, Func<CancellationToken, Task>>
        {
        { StartupTasks.AutoCleanupSeenPacketCache, ct => CleanupTasks.AutoCleanupSeenPacketCache(Node) },
        { StartupTasks.AutoCleanupIssuedTokens, ct => CleanupTasks.AutoCleanupIssuedTokens(Node) },
        { StartupTasks.AutoCleanupTokensPendingRemoval, ct => CleanupTasks.AutoCleanupTokensPendingRemoval(Node) },
        { StartupTasks.AutoEarnTokensOverTime, ct => CleanupTasks.AutoEarnTokensOverTime(Node) },
        { StartupTasks.AutoBroadcastPeerPing, ct => CleanupTasks.AutoBroadcastPeerPing(Node) },
        { StartupTasks.AutoPeriodicRebalance, ct => CleanupTasks.AutoPeriodicRebalance(Node, ct) },
        { StartupTasks.AutoCleanUpPingPals, ct => CleanupTasks.AutoCleanUpPingPals(Node, ct) },
        { StartupTasks.AutoCleanupTokenBalance, ct => CleanupTasks.AutoCleanupTokenBalance(Node, ct) }
        };


        // Dictionary mapping cleanup task names to their intervals.
        public static Dictionary<string, TimeSpan> TaskIntervals { get; } = new Dictionary<string, TimeSpan>
        {
        { "AutoCleanupSeenPacketCache", TimeSpan.FromMinutes(1) },
        { "AutoCleanupIssuedTokens", TimeSpan.FromHours(12) },
        { "AutoCleanupTokensPendingRemoval", TimeSpan.FromHours(12) },
        { "AutoEarnTokensOverTime", TimeSpan.FromHours(24) },
        { "AutoBroadcastPeerPing", TimeSpan.FromHours(24) },
        { "AutoPeriodicRebalance", TimeSpan.FromDays(14) },
        { "AutoCleanUpPingPals", TimeSpan.FromHours(24) },
        { "AutoCleanupTokenBalance", TimeSpan.FromHours(24) }
        };


        //Cleans up the Cache that stores recent messages preventing processing the same message twice.
        internal static async Task AutoCleanupSeenPacketCache(Node node)
        {
   

                DateTime now = DateTime.UtcNow;
                var expiredKeys = node.seenPackets
                    .Where(kvp => now - kvp.Value > node.cacheLifetime)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in expiredKeys)
                {
                    node.seenPackets.TryRemove(key, out _);
                }
            await Task.CompletedTask;
        }

        // Auto-cleanup function runs in the background
        internal static async Task AutoCleanupIssuedTokens(Node node)
        {
            // Initial delay 12
   
                try
                {
                    DateTime now = DateTime.UtcNow;

                    var expiredTokens = node.TokenManager.IssuedPushTokens
                        .Where(kvp => (now - kvp.Value.Timestamp).TotalHours > 48)
                        .Select(kvp => kvp.Key)
                        .ToList();

                    foreach (var key in expiredTokens)
                    {
                        if (node.TokenManager.IssuedPushTokens.TryRemove(key, out var token))
                        {
                            node.TokenManager.TokensPendingRemoval.TryAdd(now, token);
                            node.NetworkManager.SendPushTokenExtendPing(node, token.TokenId, token.ReceiverId);
                            Console.WriteLine($"Expired token {key} removed.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in token cleanup: {ex.Message}");
                }

                await Task.CompletedTask;
            }

        //This method cleans up tokens pending removal with cancellation support.
        internal static async Task AutoCleanupTokensPendingRemoval(Node node)
        {
            // Initial delay 12 hours

                try
                {
                    DateTime now = DateTime.UtcNow;

                    var tokensToRemove = node.TokenManager.TokensPendingRemoval
                        .Where(kvp => (now - kvp.Key).TotalHours > 24)
                        .Select(kvp => kvp.Key)
                        .ToList();

                    foreach (var key in tokensToRemove)
                    {
                        if (node.TokenManager.TokensPendingRemoval.TryRemove(key, out _))
                        {
                            Console.WriteLine($"Expired token {key} removed.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in token cleanup: {ex.Message}");
                }

                await Task.CompletedTask;
            
        }

        internal static async Task AutoEarnTokensOverTime(Node node)
        {

        



       
                try
                {
                    if (node.TokenManager.pingPal == null)
                    {
                        Peer peer = new Peer();
                        List<Peer> peers = node.RoutingTable.GetBestReputationPeers(node.Peer.NodeId, 10);
                        Random rnd = new Random();
                        int r = rnd.Next(peers.Count);
                        peer = peers[r];
                        node.NetworkManager.PingPalAsync(node, peer);

                         await Task.CompletedTask;
                    }
                    else
                    {
                        bool success = await node.NetworkManager.PingPalAsync(node, node.TokenManager.pingPal);

                        if (success)
                        {
                            Console.WriteLine("Successfully pinged peer for token. Selecting new PingPal");


                            Peer peer = new Peer();
                            List<Peer> peers = node.RoutingTable.GetBestReputationPeers(node.Peer.NodeId, 10);
                            Random rnd = new Random();
                            int r = rnd.Next(peers.Count);
                            peer = peers[r];
                            node.NetworkManager.PingPalAsync(node, peer);
                        }
                        else
                        {
                            Console.WriteLine("Failed to ping peer for token.");
                        }

                        await Task.CompletedTask;
                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: There was an error earning the token over time {ex.Message}");
                }
                await Task.CompletedTask;
            
        }

        // This is used to broadcast a ping to all known peers every 24 hours .
        internal static async Task AutoBroadcastPeerPing(Node node)
        {
            
                try
                {
                    Console.WriteLine("Broadcasting peer ping to all known peers...");

                    List<Peer> peers = node.RoutingTable.GetAllPeers();

                    foreach (var peer in peers)
                    {
                        node.NetworkManager.PingPeerAsync(node, peer);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in AutoBroadcastPeerPing: {ex.Message}");
                }

               
                await Task.CompletedTask;
            
        }

        //This is used to periodically re-balance the DHTs.
        internal static async Task AutoPeriodicRebalance(Node node, CancellationToken cancellationToken)
        {
            TimeSpan defaultRebalanceInterval = TimeSpan.FromDays(14);
            TimeSpan minRebalanceInterval = TimeSpan.FromDays(5);
            DateTime lastRebalance = DateTime.UtcNow;

          
                try
                {
                    if (!node.isBootstrapped)
                    {
                        Console.WriteLine("⚠️ Node is not bootstrapped. Skipping re-balance.");
                        await Task.Delay(defaultRebalanceInterval, cancellationToken);
                       
                    }

                    bool hasPeers = node.RoutingTable.GetAllPeers().Count > 0;
                    if (!hasPeers)
                    {
                        Console.WriteLine("⚠️ No peers in routing table. Skipping re-balance.");
                        await Task.Delay(defaultRebalanceInterval, cancellationToken);
                        
                    }

                    bool hasContactBlocks = node.ContactDHT.GetTotalBlockCount() > 0;
                    bool hasReputationBlocks = node.ReputationDHT.GetTotalBlockCount() > 0;
                    bool hasTransactionBlocks = node.TransactionDHT.GetTotalBlockCount() > 0;

                    bool shouldRebalanceContact = DHTManagement.HasSignificantRoutingTableChange(node, node.ContactDHT) ||
                                                  DHTManagement.HasStorageLoadChange(node.ContactDHT) ||
                                                  DHTManagement.HasHighLookupFailures(node.ContactDHT);

                    bool shouldRebalanceReputation = DHTManagement.HasSignificantRoutingTableChange(node, node.ReputationDHT) ||
                                                     DHTManagement.HasStorageLoadChange(node.ReputationDHT) ||
                                                     DHTManagement.HasHighLookupFailures(node.ReputationDHT);

                    bool shouldRebalanceTransaction = DHTManagement.HasSignificantRoutingTableChange(node, node.TransactionDHT) ||
                                                      DHTManagement.HasStorageLoadChange(node.TransactionDHT) ||
                                                      DHTManagement.HasHighLookupFailures(node.TransactionDHT);

                    if (shouldRebalanceContact && hasContactBlocks)
                    {
                        Console.WriteLine("🔄 Running ContactDHT re-balance...");
                        DHTManagement.ReassignBlocks(node, node.ContactDHT);
                        DHTManagement.FetchMissingContactBlocks(node);
                    }

                    if (shouldRebalanceReputation && hasReputationBlocks)
                    {
                        Console.WriteLine("🔄 Running ReputationDHT re-balance...");
                        DHTManagement.ReassignBlocks(node, node.ReputationDHT);
                        DHTManagement.FetchMissingReputationBlocks(node);
                    }

                    if (shouldRebalanceTransaction && hasTransactionBlocks)
                    {
                        Console.WriteLine("🔄 Running TransactionDHT re-balance...");
                        DHTManagement.ReassignBlocks(node, node.TransactionDHT);
                        DHTManagement.FetchMissingTransactionBlocks(node);
                    }

                    await Task.Delay(defaultRebalanceInterval, cancellationToken);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Error in PeriodicRebalance: {ex.Message}");
                }
                await Task.CompletedTask;
            
        }

        //This is used to clean up the pingPals every 24 hours.
        internal static async Task AutoCleanUpPingPals(Node node, CancellationToken cancellationToken)
        {

                try
                {
                    foreach (var key in node.TokenManager.pingPals.Keys.ToList())
                    {
                        if (node.TokenManager.pingPals[key] < DateTime.UtcNow.AddHours(-24))
                        {
                            node.TokenManager.pingPals.Remove(key);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: There was an error cleaning up the pingPal {ex.Message}");
                }
                await Task.CompletedTask;
            
        }

        //This is used to clean up the token balance every 24 hours.
        internal static async Task AutoCleanupTokenBalance(Node node, CancellationToken cancellationToken)
        {
                try
                {
                    // Remove usage events older than 24 hours from the log.
                    DateTime cutoff = DateTime.UtcNow - TimeSpan.FromHours(24);
                    while (node.TokenManager._tokenUsageLog.TryPeek(out DateTime usageTime) && usageTime < cutoff)
                    {
                        node.TokenManager._tokenUsageLog.TryDequeue(out _);
                    }

                    int tokensUsedLast24 = node.TokenManager._tokenUsageLog.Count;
                    int maxAllowed = node.TokenManager._baseCap + (node.TokenManager._usageMultiplier * tokensUsedLast24);

                    if (node.TokenManager.PushTokenBalance.Count > maxAllowed)
                    {
                        // Order tokens by their issuance time (oldest first)
                        var tokensOrdered = node.TokenManager.PushTokenBalance.Values.OrderBy(t => t.Timestamp).ToList();

                        foreach (var token in tokensOrdered)
                        {
                            // If the token is "stale" (held longer than the stale threshold), remove it.
                            if (DateTime.UtcNow - token.Timestamp >= node.TokenManager._staleThreshold)
                            {
                                node.TokenManager.PushTokenBalance.TryRemove(token.TokenId, out _);
                                Console.WriteLine($"Removed stale token {token.TokenId} issued at {token.Timestamp}");
                                if (node.TokenManager.PushTokenBalance.Count <= maxAllowed)
                                    break;
                            }
                        }
                    }

                }

                catch (Exception ex)
                {
                    Console.WriteLine($"AutoCleanupTokenBalance error: {ex.Message}");
                }
            await Task.CompletedTask;
        }
    }
}
