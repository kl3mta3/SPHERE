using SPHERE.Blockchain;
using SPHERE.Networking;
using SPHERE.Configure.Logging;
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
        public static Dictionary<StartupTasks, Func<Node, CancellationToken, Task>> TaskMap =
            new Dictionary<StartupTasks, Func<Node, CancellationToken, Task>>
            {
                [StartupTasks.AutoCleanupSeenPacketCache] = async (node, ct) =>
                {
                    // Pass node into your cleanup method
                    await CleanupTasks.AutoCleanupSeenPacketCache(node);
                },
                [StartupTasks.AutoCleanupIssuedTokens] = async (node, ct) =>
                {
                    await CleanupTasks.AutoCleanupIssuedTokens(node);
                },
                [StartupTasks.AutoCleanupTokensPendingRemoval] = async (node, ct) =>
                {
                    await CleanupTasks.AutoCleanupTokensPendingRemoval(node);
                },
                [StartupTasks.AutoEarnTokensOverTime] = async (node, ct) =>
                {
                    await CleanupTasks.AutoEarnTokensOverTime(node);
                },
                [StartupTasks.AutoBroadcastPeerPing] = async (node, ct) =>
                {
                    await CleanupTasks.AutoBroadcastPeerPing(node);
                },
                [StartupTasks.AutoPeriodicRebalance] = async (node, ct) =>
                {
                    await CleanupTasks.AutoPeriodicRebalance(node, ct);
                },
                [StartupTasks.AutoCleanUpPingPals] = async (node, ct) =>
                {
                    await CleanupTasks.AutoCleanUpPingPals(node, ct);
                },
                [StartupTasks.AutoCleanupTokenBalance] = async (node, ct) =>
                {
                    await CleanupTasks.AutoCleanupTokenBalance(node, ct);
                },
            };


        // Dictionary mapping cleanup task names to their intervals.
        public static Dictionary<StartupTasks, TimeSpan> TaskIntervals { get; } = new Dictionary<StartupTasks, TimeSpan>
        {
        { StartupTasks.AutoCleanupSeenPacketCache, TimeSpan.FromMinutes(1) },
        { StartupTasks.AutoCleanupIssuedTokens, TimeSpan.FromHours(12) },
        { StartupTasks.AutoCleanupTokensPendingRemoval, TimeSpan.FromHours(12) },
        { StartupTasks.AutoEarnTokensOverTime, TimeSpan.FromHours(24) },
        { StartupTasks.AutoBroadcastPeerPing, TimeSpan.FromHours(24) },
        { StartupTasks.AutoPeriodicRebalance, TimeSpan.FromDays(14) },
        { StartupTasks.AutoCleanUpPingPals, TimeSpan.FromHours(24) },
        { StartupTasks.AutoCleanupTokenBalance, TimeSpan.FromHours(24) }
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
            Reputation.PruneOldSeenReputationEntries(node);
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
                            NetworkManager.SendPushTokenExtendPing(node, token.TokenId, token.ReceiverId);
                            SystemLogger.Log($"Expired token {key} removed.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Error in token cleanup: {ex.Message}");
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
                            SystemLogger.Log($"Expired token {key} removed.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Error in token cleanup: {ex.Message}");
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
                            SystemLogger.Log("Successfully pinged peer for token. Selecting new PingPal");


                            Peer peer = new Peer();
                            List<Peer> peers = node.RoutingTable.GetBestReputationPeers(node.Peer.NodeId, 10);
                            Random rnd = new Random();
                            int r = rnd.Next(peers.Count);
                            peer = peers[r];
                            node.NetworkManager.PingPalAsync(node, peer);
                        }
                        else
                        {
                            SystemLogger.Log("Failed to ping peer for token.");
                        }

                        await Task.CompletedTask;
                    }

                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Error: There was an error earning the token over time {ex.Message}");
                }
                await Task.CompletedTask;
            
        }

        // This is used to broadcast a ping to all known peers every 24 hours .
        internal static async Task AutoBroadcastPeerPing(Node node)
        {
            
                try
                {
                    SystemLogger.Log("Broadcasting peer ping to all known peers...");

                    List<Peer> peers = node.RoutingTable.GetAllPeers();

                    foreach (var peer in peers)
                    {
                        node.NetworkManager.PingPeerAsync(node, peer);
                    }
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Error in AutoBroadcastPeerPing: {ex.Message}");
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
                        SystemLogger.Log("⚠️ Node is not bootstrapped. Skipping re-balance.");
                        await Task.Delay(defaultRebalanceInterval, cancellationToken);
                       
                    }

                    bool hasPeers = node.RoutingTable.GetAllPeers().Count > 0;
                    if (!hasPeers)
                    {
                        SystemLogger.Log("⚠️ No peers in routing table. Skipping re-balance.");
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
                        SystemLogger.Log("🔄 Running ContactDHT re-balance...");
                        DHTManagement.ReassignBlocks(node, node.ContactDHT);
                        DHTManagement.FetchMissingContactBlocks(node);
                    }

                    if (shouldRebalanceReputation && hasReputationBlocks)
                    {
                        SystemLogger.Log("🔄 Running ReputationDHT re-balance...");
                        DHTManagement.ReassignBlocks(node, node.ReputationDHT);
                        DHTManagement.FetchMissingReputationBlocks(node);
                    }

                    if (shouldRebalanceTransaction && hasTransactionBlocks)
                    {
                        SystemLogger.Log("🔄 Running TransactionDHT re-balance...");
                        DHTManagement.ReassignBlocks(node, node.TransactionDHT);
                        DHTManagement.FetchMissingTransactionBlocks(node);
                    }

                    await Task.Delay(defaultRebalanceInterval, cancellationToken);
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"❌ Error in PeriodicRebalance: {ex.Message}");
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
                    SystemLogger.Log($"Error: There was an error cleaning up the pingPal {ex.Message}");
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
                                SystemLogger.Log($"Removed stale token {token.TokenId} issued at {token.Timestamp}");
                                if (node.TokenManager.PushTokenBalance.Count <= maxAllowed)
                                    break;
                            }
                        }
                    }

                }

                catch (Exception ex)
                {
                    SystemLogger.Log($"AutoCleanupTokenBalance error: {ex.Message}");
                }
            await Task.CompletedTask;
        }
    }
}
