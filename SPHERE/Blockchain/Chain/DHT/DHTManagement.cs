using SPHERE.Configure;
using SPHERE.Configure.Logging;
using SPHERE.Networking;
using SPHERE.PacketLib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SPHERE.Blockchain
{
    /// <summary>
    /// DHTManagement is responsible for managing the Distributed Hash Table (DHT) in the blockchain.
    /// It provides dynamic load balancing and block reassignment to optimize storage and retrieval.
    /// </summary>
    internal class DHTManagement
    {

        private static int lastKnownPeerCount;
        private static Dictionary<string, int> lastKnownBlockCounts = new();
        private static Dictionary<string, int> failedBlockLookupCounts = new();

        internal static  bool HasSignificantRoutingTableChange(Node node, DHT dht)
        {
            string dhtName = dht.GetType().Name; // Get the DHT name as an identifier

            int currentPeerCount = node.RoutingTable.GetAllPeers().Count;

            
                lastKnownPeerCount = currentPeerCount; 

            bool hasChanged = Math.Abs(currentPeerCount - lastKnownPeerCount) > (lastKnownPeerCount * 0.15);

            lastKnownPeerCount = currentPeerCount; // Update the last known count

            return hasChanged;
        }

        internal static bool HasStorageLoadChange(DHT dht)
        {
            string dhtName = dht.GetType().Name; // Identify the DHT being checked

            int currentBlockCount = dht.GetTotalBlockCount();

            if (!lastKnownBlockCounts.ContainsKey(dhtName))
                lastKnownBlockCounts[dhtName] = currentBlockCount; // Initialize first run

            bool hasChanged = Math.Abs(currentBlockCount - lastKnownBlockCounts[dhtName]) > (lastKnownBlockCounts[dhtName] * 0.25);

            lastKnownBlockCounts[dhtName] = currentBlockCount; // Update stored value

            return hasChanged;
        }

        internal static bool HasHighLookupFailures(DHT dht)
        {
            string dhtName = dht.GetType().Name; // Identify the DHT being checked

            if (!failedBlockLookupCounts.ContainsKey(dhtName))
                failedBlockLookupCounts[dhtName] = 0; // Initialize counter

            return failedBlockLookupCounts[dhtName] > 50; // Threshold can be adjusted
        }

        internal static  void IncrementFailedLookups(DHT dht)
        {
            string dhtName = dht.GetType().Name;
            if (!failedBlockLookupCounts.ContainsKey(dhtName))
                failedBlockLookupCounts[dhtName] = 0;

            failedBlockLookupCounts[dhtName]++;
        }

        internal static bool IsUnderloaded(Node node, DHT dht)
        {
            int storedBlocks = dht.GetTotalBlockCount();
            return storedBlocks < EstimateIdealBlockCount(node, dht) * 0.5; // If 50% under ideal, we fetch more
        }

        private static  async Task SendBlockToPeer(Node node, Peer peer, Block block)
        {

            if (block != null)
            {
                SystemLogger.Log($"Debug-SendBlocksToPeer: {block.Header.BlockId} Block Set to send to peer");

                // Build GetResponse packet
                var responseHeader = Packet.PacketBuilder.BuildPacketHeader(
                    Packet.PacketBuilder.PacketType.SyncDHTResponse,
                    node.Peer.NodeId,
                    node.Peer.Node_Type.ToString(),
                    node.Peer.PublicSignatureKey,
                    node.Peer.PublicEncryptKey,
                    node.Client.clientListenerPort,
                    node.Client.clientIP.ToString(),
                    5
                );



                Packet responsePacket = Packet.PacketBuilder.BuildPacket(responseHeader, JsonSerializer.Serialize(block));
                byte[] serializedResponse = Packet.PacketBuilder.SerializePacket(responsePacket);

                // Encrypt with the requester's public key
                byte[] encryptedResponse = Encryption.EncryptPacketWithPublicKey(serializedResponse, peer.PublicEncryptKey);

                // Send the response to the requester
                bool success = await Client.SendPacketToPeerAsync(peer.NodeIP, peer.NodePort, encryptedResponse);

                if (success)
                    SystemLogger.Log($"Successfully sent GetResponse for {block.Header.BlockId} Blocks to {peer.NodeIP}:{peer.NodePort}");
                else
                    SystemLogger.Log($"Failed to send GetResponse for {block} Blocks to {peer.NodeIP}:{peer.NodePort}");

                return;
            }

        }

        private static bool IsOverloaded(Node node, DHT dht)
        {
            int storedBlocks = dht.GetTotalBlockCount();
            return storedBlocks > EstimateIdealBlockCount(node, dht) * 1.5; // If 50% over ideal, we re-balance
        }

        private static bool IsPeerCloser(Node node, Peer peer, string blockId)
        {
            BigInteger ourDistance = RoutingTable.CalculateXorDistance(node.Peer.NodeId, blockId);
            BigInteger peerDistance = RoutingTable.CalculateXorDistance(peer.NodeId, blockId);

            return peerDistance < ourDistance; // True if the peer is a better storage choice
        }

        private static int EstimateIdealBlockCount(Node node, DHT dht)
        {
            int totalNodes = node.RoutingTable.GetAllPeers().Count + 1;
            int totalBlocks = dht.GetTotalBlockCount();
            return totalBlocks / totalNodes;
        }

        internal static void FetchMissingContactBlocks(Node node)
        {
            if (!IsUnderloaded(node, node.ContactDHT)) return; 

            List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(node.Peer.NodeId, 5);

            foreach (var peer in closestPeers)
            {
                RequestBlocksFromPeer(node, peer, Block.BlockType.Contact);
            }
        }

        internal static void FetchMissingReputationBlocks(Node node)
        {
            if (!IsUnderloaded(node, node.ReputationDHT)) return; // Only fetch if necessary

            List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(node.Peer.NodeId, 5);

            foreach (var peer in closestPeers)
            {
                RequestBlocksFromPeer(node, peer, Block.BlockType.Reputation);
            }
        }

        internal static void FetchMissingTransactionBlocks(Node node)
        {
            if (!IsUnderloaded(node, node.TransactionDHT)) return; 

            List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(node.Peer.NodeId, 5);

            foreach (var peer in closestPeers)
            {
                RequestBlocksFromPeer(node, peer, Block.BlockType.Transaction);
            }
        }

        private static async Task RequestBlocksFromPeer(Node node, Peer peer, Block.BlockType blockType)
        {
            // Build a GetRequest packet
            var header = Packet.PacketBuilder.BuildPacketHeader(
                Packet.PacketBuilder.PacketType.SyncDHTRequest,
                node.Peer.NodeId,
                node.Peer.Node_Type.ToString(),
                node.Peer.PublicSignatureKey,
                node.Peer.PublicEncryptKey,
                node.Client.clientListenerPort,
                node.Client.clientIP.ToString(),
                15
            );

            Packet requestPacket = Packet.PacketBuilder.BuildPacket(header, blockType.ToString());
            byte[] serializedPacket = Packet.PacketBuilder.SerializePacket(requestPacket);

            // Encrypt the packet with the peer's public key
            byte[] encryptedPacket = Encryption.EncryptPacketWithPublicKey(serializedPacket, peer.PublicEncryptKey);

            // Send the request to the peer
            bool success = await Client.SendPacketToPeerAsync(peer.NodeIP, peer.NodePort, encryptedPacket);
            if (success)
            {
                SystemLogger.Log($"Successfully requested {blockType} blocks from {peer.NodeId}");
            }
            else
            {
                SystemLogger.Log($"Failed to request {blockType} blocks from {peer.NodeId}");
            }
        }

        internal static async Task ProcessSyncDHTResponse(Node node, Packet packet)
        {
            try
            {
                if (packet == null || packet.Header == null)
                {
                    SystemLogger.Log("Error-ProcessSyncDHTResponse: Received invalid SyncDHTResponse packet.");
                    return;
                }

                // Deserialize the block from the response
                var receivedBlock = JsonSerializer.Deserialize<Block>(packet.Content);
                if (receivedBlock == null || receivedBlock.Header == null)
                {
                    SystemLogger.Log("Debug-ProcessSyncDHTResponse: Error: Failed to deserialize block from SyncDHTResponse.");
                    return;
                }

                Block.BlockType blockType = Block.BlockHeader.ParseBlockType(packet.Header.Packet_Type);

                string blockId = receivedBlock.Header.BlockId;
                SystemLogger.Log($"Debug-ProcessSyncDHTResponse: Processing SyncDHTResponse for Block ID: {blockId}");


                switch (blockType)
                {
                    case Block.BlockType.Contact:

                        // Check if we already have this block
                        if (node.ContactDHT.GetBlock(blockId) != null)
                        {
                            SystemLogger.Log($"Debug-ProcessSyncDHTResponse: Block {blockId} already exists in DHT. Ignoring.");
                            return;
                        }

                        // Determine if we should store the block or forward it
                        bool underloaded = IsUnderloaded(node, node.ContactDHT);
                        bool overloaded = IsOverloaded(node, node.ContactDHT);
                        bool peerIsCloser = false;

                        List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(blockId, 5);
                        foreach (var peer in closestPeers)
                        {
                            if (IsPeerCloser(node, peer, blockId))
                            {
                                peerIsCloser = true;
                                SystemLogger.Log($"Debug-ProcessSyncDHTResponse: A closer peer found for block {blockId}: {peer.NodeId}");
                                break;
                            }
                        }

                        if (underloaded || !peerIsCloser)
                        {
                            // Store the block locally
                            SystemLogger.Log($"Debug-ProcessSyncDHTResponse: Storing block {blockId} locally.");
                            node.ContactDHT.AddBlock(receivedBlock);
                        }
                        else
                        {
                            // Forward to the closest peer
                            SystemLogger.Log($"Debug-ProcessSyncDHTResponse: Forwarding block {blockId} to a closer peer.");
                            foreach (var peer in closestPeers)
                            {
                                if (IsPeerCloser(node, peer, blockId))
                                {
                                    await SendBlockToPeer(node, peer, receivedBlock);
                                    return; // Stop after forwarding to one peer
                                }
                            }
                        }
                         break;



                    case Block.BlockType.Reputation:

                        // Check if we already have this block
                        if (node.ReputationDHT.GetBlock(blockId) != null)
                        {
                            SystemLogger.Log($"Debug-ProcessSyncDHTResponse: Block {blockId} already exists in DHT. Ignoring.");
                            return;
                        }

                        // Determine if we should store the block or forward it
                        bool _underloaded = IsUnderloaded(node, node.ReputationDHT);
                        bool _overloaded = IsOverloaded(node, node.ReputationDHT);
                        bool _peerIsCloser = false;

                        List<Peer> _closestPeers = node.RoutingTable.GetClosestPeers(blockId, 5);
                        foreach (var peer in _closestPeers)
                        {
                            if (IsPeerCloser(node, peer, blockId))
                            {
                                peerIsCloser = true;
                                SystemLogger.Log($"Debug-ProcessSyncDHTResponse: A closer peer found for block {blockId}: {peer.NodeId}");
                                break;
                            }
                        }

                        if (_underloaded || !_peerIsCloser)
                        {
                            // Store the block locally
                            SystemLogger.Log($"Debug-ProcessSyncDHTResponse: Storing block {blockId} locally.");
                            node.ReputationDHT.AddBlock(receivedBlock);
                        }
                        else
                        {
                            // Forward to the closest peer
                            SystemLogger.Log($"Forwarding block {blockId} to a closer peer.");
                            foreach (var peer in _closestPeers)
                            {
                                if (IsPeerCloser(node, peer, blockId))
                                {
                                    await SendBlockToPeer(node, peer, receivedBlock);
                                    return; // Stop after forwarding to one peer
                                }
                            }
                        }
                        break;

                    default:
                        SystemLogger.Log("Error-ProcessSyncDHTResponse: Received invalid block type in SyncDHTResponse.");
                        break;

                }

            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing SyncDHTResponse: {ex.Message}");
            }
        }

        private static int GetClosestNodeDifference(Node node, string blockId)
        {

            BigInteger ourDistance = RoutingTable.CalculateXorDistance(node.Peer.NodeId, blockId);
            BigInteger closestPeerDistance = node.RoutingTable.GetClosestPeers(blockId, 1)
                .Select(peer => RoutingTable.CalculateXorDistance(peer.NodeId, blockId))
                .FirstOrDefault();

            return (int)(ourDistance - closestPeerDistance);
        }

        internal static async Task ReassignBlocks(Node node, DHT dht)
        {
            if (!IsOverloaded(node, dht)) return; // Only re-balance if necessary

            List<Block> blocksToReassign = dht.GetCurrentState();

            // Sort blocks by which ones have closer nodes than us
            blocksToReassign = blocksToReassign
                .OrderByDescending(block => GetClosestNodeDifference(node, block.Header.BlockId))
                .Take(10) // Reassign the 10 most "misplaced" blocks
                .ToList();

            foreach (var block in blocksToReassign)
            {
                List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(block.Header.BlockId, 5);
                foreach (var peer in closestPeers)
                {
                    if (peer.NodeId != node.Peer.NodeId && IsPeerCloser(node, peer, block.Header.BlockId))
                    {
                        SendBlockToPeer(node, peer, block);

                        dht.RemoveBlock(block.Header.BlockId);
                        SystemLogger.Log($"Block {block.Header.BlockId} reassigned to {peer.NodeId}");
                        break;
                    }
                }
            }
        }

        internal static async Task ProcessSyncDHTRequest(Node node, Packet packet)
        {
            try
            {
                if (packet == null || packet.Header == null)
                {
                    SystemLogger.Log("Error-ProcessSyncDHTRequest: Received invalid SyncDHTRequest packet.");
                    return;
                }

                Block.BlockType blockType = Block.BlockHeader.ParseBlockType(packet.Content);
                Peer senderPeer= Peer.CreatePeerFromPacket(packet);

                List<Block> closestBlocks = GetClosestBlocksForPeer(node, senderPeer, blockType);

                if (closestBlocks.Count == 0)
                {
                    SystemLogger.Log($"⚠️ No blocks close to {senderPeer.NodeId} found for {blockType}.");
                    return;
                }

                SystemLogger.Log($"📤 Sending {closestBlocks.Count} closest {blockType} blocks to {senderPeer.NodeId}.");

                // Send each block in a separate task for parallel processing
                foreach (var block in closestBlocks)
                {
                    Task.Run(() => SendBlockToPeer(node, senderPeer, block));
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"❌ Error processing SyncDHTRequest: {ex.Message}");
            }
        }

        private static List<Block> GetClosestBlocksForPeer(Node node, Peer senderPeer, Block.BlockType blockType)
        {
            List<Block> allBlocks = blockType == Block.BlockType.Contact ? node.ContactDHT.GetCurrentState() : node.ReputationDHT.GetCurrentState();

            return allBlocks
                .OrderBy(block => RoutingTable.CalculateXorDistance(block.Header.BlockId, senderPeer.NodeId))
                .Take(10) // Limit to the 10 closest blocks
                .ToList();
        }
    }
}
