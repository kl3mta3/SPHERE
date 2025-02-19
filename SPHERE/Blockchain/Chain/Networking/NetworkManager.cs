using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using SPHERE.Blockchain;
using SPHERE.Configure;
using SPHERE.PacketLib;
using SPHERE.Security;

namespace SPHERE.Networking
{
    internal class NetworkManager
    {


        //-----Connection Calls-----\\

        public async Task BroadcastConnectionToNetwork(Node node)
        {
         

            try
            {
                Console.WriteLine("Debug-BrodcastConnectionToNetwork: Starting Broadcast Network Connection...");


                // Use RetryAsync to retry the operation on failure
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-BrodcastConnectionToNetwork: Broadcast  Network Connection packet...");
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.BrodcastConnection,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        50
                    );

                    Packet packet = Packet.PacketBuilder.BuildPacket(header, Packet.PacketBuilder.PacketType.BrodcastConnection.ToString());
                    Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Packet built with NodeId: {node.Peer.NodeId}, IP: {node.Client.clientIP}, Port: {node.Client.clientListenerPort}");

                    // Serialize the packet into a byte array
                    Console.WriteLine("Debug-BrodcastConnectionToNetwork: Serializing packet...");
                    byte[] data = Packet.PacketBuilder.SerializePacket(packet);
                    Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Packet serialized. Data Length: {data.Length} bytes");

                    bool allSuccessful = true;

                    List<Peer> peers = node.RoutingTable.GetAllPeers();

                    var tasks = peers.Select(async peer =>
                    {
                        Console.WriteLine("Debug-BrodcastConnectionToNetwork: Encrypting packet...");

                        try
                        {
                            // Encrypt the packet using the recipient's public communication key
                            byte[] encryptedData = Encryption.EncryptPacketWithPublicKey(data, peer.PublicEncryptKey);
                            Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Packet encrypted. Encrypted Data Length: {encryptedData.Length} bytes");

                            // Send the encrypted data and signature to the recipient
                            Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Sending packet to NODE: {peer.NodeId.Substring(0, 6)} at {peer.NodeIP}:{peer.NodePort}...");
                            bool success = await Client.SendPacketToPeerAsync(peer.NodeIP, peer.NodePort, encryptedData);

                            if (!success)
                            {
                                Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Failed to send broadcast to {peer.NodeIP}:{peer.NodePort}");
                                allSuccessful = false;
                            }
                            else
                            {
                                Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Broadcast successfully sent to {peer.NodeIP}:{peer.NodePort}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error broadcasting to {peer.NodeIP}:{peer.NodePort}: {ex.Message}");
                            allSuccessful = false;
                        }
                    });

                    // Execute all broadcasts in parallel
                    await Task.WhenAll(tasks);


                    if (!allSuccessful)
                    {
                        throw new Exception("BrodcastConnectionToNetwork: Some peers failed to receive the broadcast.");
                    }

                    // Log successful bootstrap request

                    Console.WriteLine("Debug-BrodcastConnectionToNetwork: Bootstrap Request process completed.");
                    return allSuccessful;
                });

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-BrodcastConnectionToNetwork: {ex.Message}");
                Console.WriteLine($"BrodcastConnectionToNetwork: Debug Trace: {ex.StackTrace}");
                throw;
            }

        }

        // Send response to a Ping request.
        public async Task RespondToPingAsync(Node node, Packet packet)
        {

            try
            {
                // Validate the incoming packet
                if (packet == null || packet.Header == null)
                {
                    Console.WriteLine("Invalid ping request packet.");
                    return;
                }

                string senderIPAddress = packet.Header.IPAddress;
                int senderPort = int.Parse(packet.Header.Port);
                byte[] senderPublicSignatureKey = packet.Header.PublicSignatureKey;
                byte[] senderPublicEncryptKey = packet.Header.PublicEncryptKey;

                if (string.IsNullOrWhiteSpace(senderIPAddress) || string.IsNullOrWhiteSpace(Convert.ToBase64String(senderPublicSignatureKey)))
                {
                    Console.WriteLine("Invalid ping request header details.");
                    return;
                }

                // Validate and potentially add the sender to the routing table
                lock (node.RoutingTable)
                {
                    // Create a new peer object
                    Peer newPeer = new Peer
                    {
                        NodeIP = senderIPAddress,
                        NodePort = senderPort,
                        PublicSignatureKey = senderPublicSignatureKey,
                        PublicEncryptKey = senderPublicEncryptKey,
                        NodeId = packet.Header.NodeId,
                        Reputation = 0 // Initial trust score
                    };

                    // Add the peer to the RoutingTable (handles duplicates and updates)
                    node.RoutingTable.AddPeer(newPeer);
                    Console.WriteLine($"Added or updated peer {newPeer.NodeId} in the routing table.");
                }

                // Build the ping response packet
                Packet responsePacket = new Packet
                {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = node.Peer.NodeId,
                        IPAddress = node.Client.clientIP.ToString(),
                        Port = node.Client.clientListenerPort.ToString(),
                        PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeSignatureKey),
                        PublicEncryptKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeEncryptionKey),
                        Packet_Type = "Pong",
                        TTL = "1"
                    },
                    Content = Convert.ToBase64String(Encoding.UTF8.GetBytes("Pong")),
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes("Pong")))
                };

                // Serialize and send the response packet
                byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(
                    Encoding.UTF8.GetBytes(responsePacket.Content),
                    node.Peer.PublicEncryptKey

                );

                bool success = await Client.SendPacketToPeerAsync(senderIPAddress, senderPort, encryptedResponseData);

                if (success)
                {
                    Console.WriteLine($"Successfully sent PingResponse to {senderIPAddress}:{senderPort}");
                }
                else
                {
                    Console.WriteLine($"Failed to send PingResponse to {senderIPAddress}:{senderPort}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error responding to ping: {ex.Message}");
            }
        }

        //Process Pong Response.
        public async Task ProcessPongAsync(Node node, Packet packet)
        {

            try
            {
                Peer existingPeer = node.RoutingTable.GetPeerByID(packet.Header.NodeId);

                Peer peer;
                if (existingPeer != null)
                {
                    // If peer exists, use it instead of creating a new one
                    peer = existingPeer;
                }
                else
                {
                    // Otherwise, create a new peer
                    peer = Peer.CreatePeer(
                        Enum.Parse<NodeType>(packet.Header.Node_Type),
                        packet.Header.NodeId,
                        packet.Header.IPAddress,
                        int.Parse(packet.Header.Port),
                        "Unknown",
                        packet.Header.PublicSignatureKey,
                        packet.Header.PublicEncryptKey);

                    if (!Peer.ValidatePeer(peer))
                    {
                        Console.WriteLine($"Error: Invalid peer received in Pong request.");
                        return;
                    }
                }


                node.RoutingTable.UpdatePeer(peer);
                peer.UpdateTrustScore(peer, 1);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: Failure processing Pong Request:{ex.Message}");
            }

        }


        //-----Pings-----\\

        //Ping a single peer. Returns True or false based on successful ping. 
        public static async Task<bool> PingPeerAsync(Node node, Peer peer)
        {
            try
            {
                // Send a small ping packet to the peer
                Packet pingPacket = new Packet
                {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = node.Peer.NodeId,
                        IPAddress = node.Peer.NodeIP,
                        Port = node.Peer.NodePort.ToString(),
                        PublicSignatureKey = node.Peer.PublicSignatureKey,
                        PublicEncryptKey = node.Peer.PublicEncryptKey,
                        Packet_Type = "Ping",
                        TTL = "1"
                    },
                    Content = Convert.ToBase64String(Encoding.UTF8.GetBytes("PingRequest")),
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes("PingRequest")))
                };

                // Send the ping and wait for a response
                bool success = await Client.SendPacketToPeerAsync(
                    peer.NodeIP,
                    peer.NodePort,
                    Encoding.UTF8.GetBytes(pingPacket.Content)


                );

                return success; // Return true if the ping was successful
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error pinging peer {peer.NodeId}: {ex.Message}");
                return false; // Return false if there was an error
            }
        }

        //Send a Push Token Extend Ping to the receiver.
        public async Task SendPushTokenExtendPing(Node node, string tokenId, string receiverId)
        {

            //look up the receiver in the routing table.
            Peer receiver = node.RoutingTable.GetPeerByID(receiverId);
            if (receiver == null)
            {
                Console.WriteLine("Receiver not found in routing table.");
                return;
            }
            //we will send a push token extend ping to the receiver.
            //They will then send a push token extend pong to us that includes the original Token as proof or a Failed pong if they can not.
        }
        

        //-----Peers-----\\

        //Send Peer List to requesting peer.
        public async Task PeerListResponse(Node node, Packet packet)
        {

            try
            {
                Console.WriteLine("Debug-PeerListResponse: Starting to send bootstrap response...");
                Peer peer = Peer.CreatePeer(
                    Enum.Parse<NodeType>(packet.Header.Node_Type),
                    packet.Header.NodeId,
                    packet.Header.IPAddress,
                    int.Parse(packet.Header.Port),
                    "Unknown",
                    packet.Header.PublicSignatureKey,
                    packet.Header.PublicEncryptKey);

                if (!node.RoutingTable.GetAllPeers().Contains(peer) || peer.NodeId != node.Peer.NodeId)
                {
                    node.RoutingTable.AddPeer(peer);
                }

                // Extract recipient details from the packet
                string recipientsID = packet.Header.NodeId;
                string recipientIPAddress = packet.Header.IPAddress;
                int recipientPort = int.Parse(packet.Header.Port);
                byte[] recipientPublicEncryptKey = packet.Header.PublicEncryptKey;

                Console.WriteLine($"Debug-PeerListResponse: Recipient details - NodeId: {recipientsID}, IP: {recipientIPAddress}, Port: {recipientPort}, PublicComKey: {recipientPublicEncryptKey}");

                // Validate inputs
                if (packet == null)
                {
                    Console.WriteLine("Debug-PeerListResponse: Packet is null.");
                    throw new ArgumentNullException(nameof(packet), "Packet cannot be null.");
                }

                if (node == null)
                {
                    Console.WriteLine("Debug-PeerListResponse: Node is null.");
                    throw new ArgumentNullException(nameof(node), "The Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(recipientIPAddress))
                {
                    Console.WriteLine("Debug-PeerListResponse: Recipient IP address is invalid.");
                    throw new ArgumentException("Packet's IP address cannot be null or empty.", nameof(recipientIPAddress));
                }

                if (recipientPort <= 0 || recipientPort > 65535)
                {
                    Console.WriteLine($"Debug-PeerListResponse: Invalid recipient port: {recipientPort}");
                    throw new ArgumentOutOfRangeException(nameof(recipientPort), "Packet port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(Convert.ToBase64String(recipientPublicEncryptKey)))
                {
                    Console.WriteLine("Debug-PeerListResponse: Recipient's public encryption key is invalid.");
                    throw new ArgumentException("Recipient's public encryption key cannot be null or empty.", nameof(recipientPublicEncryptKey));
                }

                Console.WriteLine("Debug-PeerListResponse: Inputs validated successfully.");

                // Use RetryAsync to ensure the response is sent
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-PeerListResponse: Preparing peer list for response...");
                    List<Peer> peerList;

                    lock (node.RoutingTable)
                    {
                        if (!string.IsNullOrWhiteSpace(recipientsID))
                        {
                            peerList = node.RoutingTable.GetClosestPeers(recipientsID, 20); // Adjust '20' as needed
                            Console.WriteLine($"Debug-PeerListResponse: Retrieved {peerList.Count} closest peers for NodeId {recipientsID}.");
                        }
                        else
                        {
                            peerList = node.RoutingTable.GetAllPeers();
                            Console.WriteLine($"Debug-PeerListResponse: Retrieved all peers. Total: {peerList.Count}");
                        }
                    }

                    Console.WriteLine($"Debug-PeerListResponse: Peer list prepared. Count: {peerList.Count}");


                    //build packet header
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.PeerUpdate,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        1

                     );



                    Packet responsePacket = Packet.PacketBuilder.BuildPacket(header, JsonSerializer.Serialize(peerList));

                    Console.WriteLine("Debug-PeerListResponse: Serializing response payload...");
                    byte[] responseData = Packet.PacketBuilder.SerializePacket(responsePacket);
                    Console.WriteLine($"Debug-PeerListResponse: Serialized response payload. Size: {responseData.Length} bytes");
                    bool success = new bool();

                    // Encrypt the response data using the recipient's public communication key
                    Console.WriteLine("Debug-PeerListResponse: Encrypting response data...");



                    byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(responseData, recipientPublicEncryptKey);

                    // Send the encrypted response data and signature to the recipient
                    Console.WriteLine($"Debug-PeerListResponse: Sending response to {recipientIPAddress}:{recipientPort}...");
                    success = await Client.SendPacketToPeerAsync(recipientIPAddress, recipientPort, encryptedResponseData);



                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug-PeerListResponse: Failed to send Peer List Response to {recipientIPAddress}:{recipientPort}");
                        throw new Exception($"PeerListResponse: Failed to send Peer List Response to {recipientIPAddress}:{recipientPort}.");
                    }

                    // Reward the recipient with a trust score for a valid request
                    Console.WriteLine("Debug-PeerListResponse: Updating trust score for recipient...");
                    lock (node.RoutingTable)
                    {
                        var peer = node.RoutingTable.GetPeerByIPAddress(recipientIPAddress);
                        if (peer != null)
                        {
                            peer.UpdateTrustScore(peer, +5); // Reward 5 points
                            Console.WriteLine($"Debug-PeerListResponse: Trust score updated for peer {peer.NodeId}. New Trust Score: {peer.Reputation}");
                        }
                        else
                        {
                            Console.WriteLine("Debug-PeerListResponse: Recipient peer not found in the routing table.");
                        }
                    }

                    // Log successful bootstrap response
                    Console.WriteLine($"Debug-PeerListResponse: Peer List Responsesuccessfully sent to {recipientIPAddress}:{recipientPort}.");

                    await node.Client.BroadcastToPeerList(node, packet);
                    return success; // Explicitly return success

                });

                Console.WriteLine("Debug-PeerListResponse: Peer List Response process completed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-PeerListResponse: {ex.Message}");
                Console.WriteLine($"PeerListResponse: Debug Trace: {ex.StackTrace}");
                throw;
            }


        }
        

        //-----Node Get Calls-----\\

        //Request a block from the network.
        public static async Task RequestBlockFromNetwork(Node node, string blockId)
        {
            try
            {
                if (node == null)
                {
                    throw new ArgumentNullException(nameof(node), "Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(blockId))
                {
                    throw new ArgumentException("Block ID cannot be null or empty.", nameof(blockId));
                }

                var existingBlock = node.ContactDHT.GetBlock(blockId);
                if (existingBlock != null)
                {
                    Console.WriteLine("Block already exists locally.");
                    return;

                }

                //We add it to requested blocks.  So we can only add GetResponses in requestedBlocks.
                if (!node.requestedBlocks.TryAdd(blockId, DateTime.UtcNow))
                {
                    Console.WriteLine($"Block {blockId} is already requested. Skipping redundant request.");
                    return;
                }

                // Get the closest peers to request the block from
                List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(blockId, 5);
                if (closestPeers.Count == 0)
                {
                    Console.WriteLine("No peers available to request the block from.");
                    return;

                }


                // Build a GetRequest packet
                var header = Packet.PacketBuilder.BuildPacketHeader(
                    Packet.PacketBuilder.PacketType.GetRequest,
                    node.Peer.NodeId,
                    node.Peer.Node_Type.ToString(),
                    node.Peer.PublicSignatureKey,
                    node.Peer.PublicEncryptKey,
                    node.Client.clientListenerPort,
                    node.Client.clientIP.ToString(),
                    15 // TTL value
                );

                Packet requestPacket = Packet.PacketBuilder.BuildPacket(header, blockId);
                byte[] serializedPacket = Packet.PacketBuilder.SerializePacket(requestPacket);


                // Iterate through the closest peers and send the request
                var tasks = closestPeers.Select(async peer =>
                {
                    Console.WriteLine($"Sending block request to peer: {peer.NodeIP}:{peer.NodePort}");

                    try
                    {

                        byte[] encryptedPacket = Encryption.EncryptPacketWithPublicKey(serializedPacket, peer.PublicEncryptKey);


                        bool success = await Client.SendPacketToPeerAsync(peer.NodeIP, peer.NodePort, encryptedPacket);

                        if (!success)
                        {
                            Console.WriteLine($"Failed to request block {blockId} from {peer.NodeIP}:{peer.NodePort}");

                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error sending request to {peer.NodeIP}:{peer.NodePort}: {ex.Message}");
                    }
                });

                // Execute all requests in parallel
                await Task.WhenAll(tasks);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error requesting block: {ex.Message}");

            }

        }

        //Respond to a GetRequest.
        public async Task RespondToGetRequest(Node node, Packet packet)
        {

            try
            {

                if (packet == null || packet.Header == null)
                {
                    Console.WriteLine("Received an invalid GetRequest packet.");
                    return;
                }

                if (!int.TryParse(packet.Header.TTL, out int ttlValue) || ttlValue <= 0)
                {
                    Console.WriteLine("Invalid or expired TTL. Dropping request.");
                    return;
                }

                int newTTL = ttlValue - 1;

                var requestedBlockIds = JsonSerializer.Deserialize<List<string>>(packet.Content);

                Console.WriteLine($"Received GetRequest for Block ID: {requestedBlockIds}");


                List<Block> requestedBlocks = new List<Block>();
                List<string> notFoundBlocks = new List<string>();


                //  Check if we already have the requested block
                foreach (var blockId in requestedBlockIds)
                {
                    Block block = node.ContactDHT.GetBlock(blockId);

                    if (block != null)
                    {
                        Console.WriteLine($"Block {blockId} found locally. Adding to response list.");
                        requestedBlocks.Add(block);
                    }
                    else
                    {
                        Console.WriteLine($"Block {blockId} not found locally. Adding to not found list.");
                        notFoundBlocks.Add(blockId);
                    }
                }



                if (requestedBlocks.Count > 0)
                {
                    Console.WriteLine($"Block {requestedBlockIds.Count} found locally. Sending GetResponse to requester...");

                    BlockResponsePayload payload = new BlockResponsePayload
                    {
                        Type = requestedBlocks[0].Header.BlockType,
                        Blocks = requestedBlocks
                    };


                    // Build GetResponse packet
                    var responseHeader = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.GetResponse,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        5 // TTL value for response
                    );



                    Packet responsePacket = Packet.PacketBuilder.BuildPacket(responseHeader, JsonSerializer.Serialize(payload));
                    byte[] serializedResponse = Packet.PacketBuilder.SerializePacket(responsePacket);

                    // Encrypt with the requester's public key
                    byte[] encryptedResponse = Encryption.EncryptPacketWithPublicKey(serializedResponse, packet.Header.PublicEncryptKey);

                    // Send the response to the requester
                    bool success = await Client.SendPacketToPeerAsync(packet.Header.IPAddress, int.Parse(packet.Header.Port), encryptedResponse);
                    if (success)
                        Console.WriteLine($"Successfully sent GetResponse for {requestedBlockIds.Count} Blocks to {packet.Header.IPAddress}:{packet.Header.Port}");
                    else
                        Console.WriteLine($"Failed to send GetResponse for {requestedBlockIds} Blocks to {packet.Header.IPAddress}:{packet.Header.Port}");

                    return;
                }

                // Block not found, rebroadcast the request to the closest peers
                Console.WriteLine($"Blocks not found locally. Rebroadcasting request to peers...");

                foreach (var Ids in notFoundBlocks)
                {

                    // Get closest peers
                    List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(Ids, 5);
                    if (closestPeers.Count == 0)
                    {
                        Console.WriteLine("No peers available to forward the request.");
                        continue;
                    }

                    packet.Header.TTL = newTTL.ToString();

                    byte[] serializedPacket = Packet.PacketBuilder.SerializePacket(packet);

                    var tasks = closestPeers.Select(async peer =>
                    {
                        Console.WriteLine($"Forwarding GetRequest for Block {Ids} to {peer.NodeIP}:{peer.NodePort}");

                        try
                        {
                            byte[] encryptedPacket = Encryption.EncryptPacketWithPublicKey(serializedPacket, peer.PublicEncryptKey);
                            await Client.SendPacketToPeerAsync(peer.NodeIP, peer.NodePort, encryptedPacket);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error forwarding GetRequest to {peer.NodeIP}:{peer.NodePort}: {ex.Message}");
                        }
                    });

                    await Task.WhenAll(tasks); // Efficient parallel execution
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing GetRequest: {ex.Message}");
            }

        }

        //Process GetResponse.
        public async Task ProcessGetResponse(Node node, Packet packet)
        {
            

            try
            {
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    Console.WriteLine("Received an invalid GetResponse packet.");
                    return;
                }

                // Deserialize the payload
                BlockResponsePayload payload = JsonSerializer.Deserialize<BlockResponsePayload>(packet.Content);

                if (payload == null || payload.Blocks == null || payload.Blocks.Count == 0)
                {
                    Console.WriteLine("Received an empty or invalid GetResponse payload.");
                    return;
                }

                // Process each block in the response
                foreach (var block in payload.Blocks)
                {
                    if (block == null || string.IsNullOrWhiteSpace(block.Header.BlockId))
                    {
                        Console.WriteLine("Received an invalid block in GetResponse.");
                        continue;
                    }

                    // Check if the block is already requested
                    if (!node.requestedBlocks.ContainsKey(block.Header.BlockId))
                    {
                        Console.WriteLine($"Block {block.Header.BlockId} was not requested. Ignoring.");
                        continue;
                    }

                    // Add the block to the DHT
                    node.ContactDHT.AddBlock(block);

                    // Remove the block from the requested list
                    node.requestedBlocks.TryRemove(block.Header.BlockId, out _);

                    Console.WriteLine($"Successfully added block {block.Header.BlockId} to the DHT.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing GetResponse: {ex.Message}");
            }
        }


        //-----Configuration Calls-----\\

        // This is used to allow for retries on sending out messages to other nodes.
        internal async Task<T> RetryAsync<T>(Func<Task<T>> action, int maxRetries = 3, int delayMilliseconds = 1000)
        {
            for (int i = 0; i < maxRetries; i++)
            {
                try
                {
                    return await action(); // Attempt the action
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Attempt {i + 1} failed: {ex.Message}");
                    if (i == maxRetries - 1)
                        throw; // Re-throw on final attempt

                    await Task.Delay(delayMilliseconds * (int)Math.Pow(2, i)); // Exponential backoff
                }
            }

            throw new Exception("RetryAsync failed after all attempts."); // Should never reach here
        }

        //same thing here, This is used to assist in retying and queuing the tasks.. 
        private async Task SafeTask(Func<Task> action)
        {
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Task error: {ex.Message}");
            }
        }

    }
}
