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
    internal class AutomaticFunctions
    {
      
        //Cleans up the Cache that stores recent messages preventing processing the same message twice.
        internal async Task StartSeenPacketCacheCleanup(Node node, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                // Attempt the delay with cancellation support
                try
                {
                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    // We got canceled during the delay—time to bounce
                    break;
                }

                DateTime now = DateTime.UtcNow;
                var expiredKeys = node.seenPackets
                    .Where(kvp => now - kvp.Value > node.cacheLifetime)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (var key in expiredKeys)
                {
                    node.seenPackets.TryRemove(key, out _);
                }
            }
        }

        // Auto-cleanup function runs in the background
        internal async Task AutoCleanupIssuedTokens(Node node, CancellationToken cancellationToken)
        {
            // Initial delay (supports cancellation)
            try
            {
                await Task.Delay(TimeSpan.FromHours(12), cancellationToken);
            }
            catch (TaskCanceledException)
            {
                // If cancellation is requested before the first delay completes
                return;
            }

            while (!cancellationToken.IsCancellationRequested)
            {
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

                // Delay again (supports cancellation)
                try
                {
                    await Task.Delay(TimeSpan.FromHours(12), cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    // If cancellation is requested during the delay
                    break;
                }
            }
        }

        //This method cleans up tokens pending removal with cancellation support.
        internal async Task AutoCleanupTokensPendingRemoval(Node node, CancellationToken cancellationToken)
        {
            // Initial delay 
            await Task.Delay(TimeSpan.FromHours(12), cancellationToken);

            while (!cancellationToken.IsCancellationRequested)
            {
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

                try
                {

                    await Task.Delay(TimeSpan.FromHours(12), cancellationToken);
                }
                catch (TaskCanceledException)
                {

                    break;
                }
            }
        }

        // This is used to broadcast a ping to all known peers every 24 hours .
        internal async Task AutoBroadcastPeerPing(Node node, CancellationToken cancellationToken)
        {
            // Initial delay with cancellation.
            await Task.Delay(TimeSpan.FromHours(24), cancellationToken);

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    Console.WriteLine("Broadcasting peer ping to all known peers...");

                    List<Peer> peers = node.RoutingTable.GetAllPeers();

                    foreach (var peer in peers)
                    {
                        NetworkManager.PingPeerAsync(node, peer);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in AutoBroadcastPeerPing: {ex.Message}");
                }

                try
                {
                    // Delay again with cancellation support.
                    await Task.Delay(TimeSpan.FromHours(24), cancellationToken);
                }
                catch (TaskCanceledException)
                {
                    // Gracefully exit when cancellation is requested.
                    break;
                }
            }
        }

        //This is used to periodically re-balance the DHTs.
        internal async Task PeriodicRebalance(Node node, CancellationToken cancellationToken)
        {
            TimeSpan defaultRebalanceInterval = TimeSpan.FromDays(14);
            TimeSpan minRebalanceInterval = TimeSpan.FromDays(5);
            DateTime lastRebalance = DateTime.UtcNow;

            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    if (!node.isBootstrapped)
                    {
                        Console.WriteLine("⚠️ Node is not bootstrapped. Skipping re-balance.");
                        await Task.Delay(defaultRebalanceInterval, cancellationToken);
                        continue;
                    }

                    bool hasPeers = node.RoutingTable.GetAllPeers().Count > 0;
                    if (!hasPeers)
                    {
                        Console.WriteLine("⚠️ No peers in routing table. Skipping re-balance.");
                        await Task.Delay(defaultRebalanceInterval, cancellationToken);
                        continue;
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
            }
        }

    }
}
