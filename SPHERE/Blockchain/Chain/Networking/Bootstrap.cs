using SPHERE.Blockchain;
using SPHERE.PacketLib;
using SPHERE.Configure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace SPHERE.Networking
{
    internal class Bootstrap
    {

        public static async Task SendBootstrapRequest(Node node, string iPAddress, int port, byte[] recipientsPublicEncryptKey)
        {


            try
            {
                Console.WriteLine($"Debug-SendBootstrapRequest: Starting Bootstrap Request...babyNodeID: {node.Peer.NodeId}");
                // Validate inputs
                if (node == null)
                {
                    Console.WriteLine("Debug: Node is null.");
                    throw new ArgumentNullException(nameof(node), "Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(iPAddress))
                {
                    Console.WriteLine("Debug: Invalid IP address input.");
                    throw new ArgumentException("IP address cannot be null or empty.", nameof(iPAddress));
                }

                if (port <= 0 || port > 65535)
                {
                    Console.WriteLine($"Debug: Invalid port: {port}.");
                    throw new ArgumentOutOfRangeException(nameof(port), "Port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(Convert.ToBase64String(recipientsPublicEncryptKey)))
                {
                    Console.WriteLine("Debug: Recipient's public communication key is null or empty.");
                    throw new ArgumentException("Recipient's public communication key cannot be null or empty.", nameof(recipientsPublicEncryptKey));
                }

                Console.WriteLine($"Debug-SendBootstrapRequest: Inputs validated. IP: {iPAddress}, Port: {port}, PublicEncryptKey: {recipientsPublicEncryptKey}");

                // Use RetryAsync to retry the operation on failure
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-SendBootstrapRequest: Building bootstrap request packet...");
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.BootstrapRequest,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        25
                    );

                    Packet packet = Packet.PacketBuilder.BuildPacket(header, Packet.PacketBuilder.PacketType.BootstrapRequest.ToString());
                    Console.WriteLine($"Debug-SendBootstrapRequest: Packet built with NodeId: {node.Peer.NodeId}, IP: {node.Client.clientIP}, Port: {node.Client.clientListenerPort}");

                    // Serialize the packet into a byte array
                    Console.WriteLine("Debug-SendBootstrapRequest: Serializing packet...");
                    byte[] data = Packet.PacketBuilder.SerializePacket(packet);
                    Console.WriteLine($"Debug-SendBootstrapRequest: Packet serialized. Data Length: {data.Length} bytes");

                    bool success = new bool();

                    // Encrypt the packet using the recipient's public communication key
                    byte[] encryptedData = Encryption.EncryptPacketWithPublicKey(data, recipientsPublicEncryptKey);
                    Console.WriteLine($"Debug-SendBootstrapRequest: Packet encrypted. Encrypted Data Length: {encryptedData.Length} bytes");


                    // Send the encrypted data and signature to the recipient
                    Console.WriteLine($"Debug-SendBootstrapRequest: Sending packet to {iPAddress}:{port}...");
                    success = await Client.SendPacketToPeerAsync(iPAddress, port, encryptedData);

                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug-SendBootstrapRequest: Failed to send bootstrap request to {iPAddress}:{port}");
                        throw new Exception($"SendBootstrapRequest: Failed to send bootstrap request to {iPAddress}:{port}.");
                    }

                    // Log successful bootstrap request
                    Console.WriteLine($"Debug-SendBootstrapRequest: Bootstrap request successfully sent to {iPAddress}:{port}");

                    Console.WriteLine("Debug-SendBootstrapRequest: Bootstrap Request process completed.");
                    return success;
                });

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-SendBootstrapRequest: {ex.Message}");
                Console.WriteLine($"SendBootstrapRequest: Debug Trace: {ex.StackTrace}");
                throw;
            }
        }

        //Process Bootstrap Response
        internal static async Task ProcessBootstrapResponse(Node node, Packet packet)
        {

            int trustScoreUpdate = 0;
            Peer senderPeer = node.RoutingTable.GetPeerByID(packet.Header.NodeId);
            if (senderPeer == null)
            {
                Console.WriteLine($"Warning: Sender {packet.Header.NodeId} is not in routing table. Adding Peer");
                senderPeer = Peer.CreatePeerFromPacket(packet);
                node.RoutingTable.AddPeer(senderPeer);

            }
            Console.WriteLine($"Debug-ProcessBootstrapResponse: This NodeID: {packet.Header.NodeId}");
            Console.WriteLine($"Debug-ProcessBootstrapResponse: Sender NodeID: {senderPeer.NodeId}.");

            try
            {
                Console.WriteLine("Debug-ProcessBootstrapResponse: Starting to process bootstrap response...");

                // Verify Node isn't already Bootstrapped, prevents re-bootstrapping by accident
                if (node.isBootstrapped)
                {
                    Console.WriteLine("Debug-ProcessBootstrapResponse: Node is already bootstrapped. Ignoring the response.");
                    return;
                }

                // Validate the packet and extract the header details
                if (packet == null || packet.Header == null)
                {
                    Console.WriteLine("Debug-ProcessBootstrapResponse: Invalid packet or missing header.");
                    trustScoreUpdate = -10;
                    senderPeer.UpdateTrustScore(senderPeer, trustScoreUpdate);
                    return;
                }

                Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing packet from Node ID: {packet.Header.NodeId}, IP: {packet.Header.IPAddress}, Port: {packet.Header.Port}");

                // De-serialize the response payload
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                BootstrapResponsePayload responsePayload = JsonSerializer.Deserialize<BootstrapResponsePayload>(packet.Content, options);

                if (responsePayload == null)
                {
                    Console.WriteLine("Debug-ProcessBootstrapResponse: Failed to deserialize bootstrap response payload.");
                    return;
                }
                Console.WriteLine("Debug-ProcessBootstrapResponse: Bootstrap response payload deserialized successfully.");

                // Process the peer list
                if (responsePayload.Peers != null)
                {
                    Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing {responsePayload.Peers.Count} peers...");

                    int invalidPeers = 0;
                    int maxAllowedInvalidPeers = 15;
                    int penaltyThreshold = 5;

                    foreach (var peer in responsePayload.Peers)
                    {

                        bool isValidPeer = false;
                        try
                        {
                            isValidPeer = Peer.ValidatePeer(peer);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error-ProcessBootstrapResponse: {ex.Message}");
                        }

                        if (peer == null || !isValidPeer)
                        {
                            invalidPeers++;

                            // Apply trust penalties at specific thresholds
                            if (invalidPeers == penaltyThreshold)
                            {
                                trustScoreUpdate -= 5; // Moderate penalty
                            }
                            else if (invalidPeers >= penaltyThreshold && invalidPeers < maxAllowedInvalidPeers)
                            {
                                trustScoreUpdate--; // Minor penalty for additional invalid peers
                            }
                            else if (invalidPeers >= maxAllowedInvalidPeers)
                            {
                                Console.WriteLine($"Debug-ProcessBootstrapResponse: Too Many Invalid Peers. Applying severe penalty.");
                                trustScoreUpdate--;
                                break;
                            }
                            continue;
                        }

                        // Add the peer to the RoutingTable (will handle duplicates automatically)
                        node.RoutingTable.AddPeer(peer);
                        trustScoreUpdate++;
                        Console.WriteLine($"Debug-ProcessBootstrapResponse: Added or updated peer {peer.NodeId} in the routing table.");

                    }

                    // Process the DHT state (if included)
                    if (responsePayload.DHT != null)
                    {
                        int validDHTBlocks = 0;
                        int invalidBlockThreshhold = 5;
                        int invalidDHTBlocks = 0;
                        int maxInvalidBlock = 15;

                        Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing {responsePayload.DHT.Count} DHT blocks...");
                        lock (Node.stateLock) // Ensure thread-safe access to the DHT
                        {
                            foreach (var block in responsePayload.DHT)
                            {
                                // Validate the block before adding it
                                if (node.ContactDHT.IsBlockValid(block))
                                {
                                    node.ContactDHT.AddBlock(block);
                                    trustScoreUpdate++;
                                    validDHTBlocks++;
                                    Console.WriteLine($"Debug-ProcessBootstrapResponse: Added DHT block: {block.Header.BlockId}");
                                }
                                else
                                {
                                    Console.WriteLine($"Debug-ProcessBootstrapResponse: Invalid block {block.Header.BlockId}. Skipping.");

                                    invalidDHTBlocks++;

                                }

                                if (invalidDHTBlocks >= maxInvalidBlock)
                                {
                                    trustScoreUpdate--;
                                    break;
                                }
                                else if (invalidDHTBlocks >= invalidBlockThreshhold)
                                {
                                    trustScoreUpdate -= invalidBlockThreshhold;
                                }
                                else if (invalidDHTBlocks > 0)
                                {
                                    trustScoreUpdate--;
                                }

                            }
                        }

                        Console.WriteLine("Debug-ProcessBootstrapResponse: Bootstrap response processed successfully.");
                    }

                    if (trustScoreUpdate != 0)
                    {
                        senderPeer.UpdateTrustScore(senderPeer, trustScoreUpdate);
                        Console.WriteLine($"Debug-ProcessBootstrapResponse: TrustScore added {senderPeer.Reputation}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-ProcessBootstrapResponse: {ex.Message}");
                Console.WriteLine($"ProcessBootstrapResponse: Debug Trace: {ex.StackTrace}");
            }

        }

        // Sends a response to a request to Bootstrap.  Sends a peer list and copy of DHT (Or shards at some point)
        internal static  async Task SendBootstrapResponse(Node node, Packet packet)
        {
            Peer senderPeer = Peer.CreatePeerFromPacket(packet);

            if (node.RoutingTable.GetPeerByID(packet.Header.NodeId) == null)
            {
                node.RoutingTable.AddPeer(senderPeer);


            }

            if (senderPeer == null)
            {
                Console.WriteLine($"Warning: Sender {packet.Header.NodeId} is not in routing table. Adding Peer");
                return;
            }

            Console.WriteLine($"Debug-ProcessBootstrapResponse: This NodeID: {packet.Header.NodeId}");
            Console.WriteLine($"Debug-ProcessBootstrapResponse: Sender NodeID: {senderPeer.NodeId}.");

            try
            {
                Console.WriteLine("Debug-SendBootstrapResponse: Starting to send bootstrap response...");

                // Extract recipient details from the packet
                string recipientsID = packet.Header.NodeId;
                string recipientIPAddress = packet.Header.IPAddress;
                int recipientPort = int.Parse(packet.Header.Port);
                byte[] recipientPublicEncryptKey = packet.Header.PublicEncryptKey;

                Console.WriteLine($"Debug-SendBootstrapResponse: Recipient details - NodeId: {recipientsID}, IP: {recipientIPAddress}, Port: {recipientPort}, PublicComKey: {recipientPublicEncryptKey}");

                // Validate inputs
                if (packet == null)
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Packet is null.");
                    throw new ArgumentNullException(nameof(packet), "Packet cannot be null.");
                }

                if (node == null)
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Node is null.");
                    throw new ArgumentNullException(nameof(node), "The Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(recipientIPAddress))
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Recipient IP address is invalid.");
                    throw new ArgumentException("Packet's IP address cannot be null or empty.", nameof(recipientIPAddress));
                }

                if (recipientPort <= 0 || recipientPort > 65535)
                {
                    Console.WriteLine($"Debug-SendBootstrapResponse: Invalid recipient port: {recipientPort}");
                    throw new ArgumentOutOfRangeException(nameof(recipientPort), "Packet port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(Convert.ToBase64String(recipientPublicEncryptKey)))
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Recipient's public encryption key is invalid.");
                    throw new ArgumentException("Recipient's public encryption key cannot be null or empty.", nameof(recipientPublicEncryptKey));
                }

                Console.WriteLine("Debug-SendBootstrapResponse: Inputs validated successfully.");

                // Use RetryAsync to ensure the response is sent
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Preparing peer list for response...");
                    List<Peer> peerList = new List<Peer>();

                    // Prepare a lightweight peer list for the response payload
                    if (!string.IsNullOrWhiteSpace(recipientsID))
                    {
                        peerList = node.RoutingTable.GetClosestPeers(recipientsID, 10);
                        Console.WriteLine($"Debug-SendBootstrapResponse: Retrieved {peerList.Count} closest peers for NodeId {recipientsID}.");
                    }
                    else
                    {
                        peerList = node.RoutingTable.GetAllPeers();
                        Console.WriteLine($"Debug-SendBootstrapResponse: Retrieved all peers. Total: {peerList.Count}");
                    }

                    Console.WriteLine($"Debug-SendBootstrapResponse: Peer list prepared. Count: {peerList.Count}");

                    // Include DHT state (if necessary)
                    var dhtState = node.ContactDHT.GetCurrentState();
                    Console.WriteLine($"Debug-SendBootstrapResponse: Prepared DHT state. Block count: {dhtState.Count}");

                    //build packet header
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.BootstrapResponse,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        1

                     );

                    // Build the response payload
                    BootstrapResponsePayload responsePayload = new BootstrapResponsePayload
                    {
                        Peers = peerList,
                        DHT = dhtState
                    };

                    var SerializedPayload = JsonSerializer.Serialize<BootstrapResponsePayload>(responsePayload);

                    Packet responsePacket = Packet.PacketBuilder.BuildPacket(header, SerializedPayload);

                    byte[] serializedPacket = Packet.PacketBuilder.SerializePacket(responsePacket);

                    Console.WriteLine($"Debug-SendBootstrapResponse: Serialized response payload. Size: {serializedPacket.Length} bytes");

                    bool success = new bool();

                    // Encrypt the response data using the recipient's public communication key
                    byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(serializedPacket, recipientPublicEncryptKey);
                    Console.WriteLine($"Debug-SendBootstrapResponse: Encrypted response data. Encrypted size: {encryptedResponseData.Length} bytes");

                    // Send the encrypted response data and signature to the recipient
                    Console.WriteLine($"Debug-SendBootstrapResponse: Sending response to {recipientIPAddress}:{recipientPort}...");
                    success = await Client.SendPacketToPeerAsync(recipientIPAddress, recipientPort, encryptedResponseData);


                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug-SendBootstrapResponse: Failed to send bootstrap response to {recipientIPAddress}:{recipientPort}");
                        throw new Exception($"SendBootstrapResponse: Failed to send bootstrap response to {recipientIPAddress}:{recipientPort}.");
                    }

                    // Reward the recipient with a trust score for a valid request
                    Console.WriteLine("Debug-SendBootstrapResponse: Updating trust score for recipient...");


                    var peer = node.RoutingTable.GetPeerByIPAddress(recipientIPAddress);

                    if (peer != null)
                    {
                        peer.UpdateTrustScore(peer, +5); // Reward 5 points
                        Console.WriteLine($"Debug-SendBootstrapResponse: Trust score updated for peer {peer.NodeId}. New Trust Score: {peer.Reputation}");
                    }
                    else
                    {
                        Console.WriteLine("Debug-SendBootstrapResponse: Recipient peer not found in the routing table.");
                    }


                    // Log successful bootstrap response
                    Console.WriteLine($"Debug-SendBootstrapResponse: Bootstrap response successfully sent to {recipientIPAddress}:{recipientPort}.");
                    return success; // Explicitly return success
                });

                Console.WriteLine("Debug-SendBootstrapResponse: Bootstrap response process completed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-SendBootstrapResponse: {ex.Message}");
                Console.WriteLine($"SendBootstrapResponse: Debug Trace: {ex.StackTrace}");
                throw;
            }
        }

        //Resets the Bootstrap Status to allow a corrupted node to "Reset" it's peers and DHT.
        public static void ResetBootstrapStatus(Node node)
        {
            node.RoutingTable.ClearRoutingTable();

            node.ContactDHT.ClearState();
            node.ReputationDHT.ClearState();
            node.TransactionDHT.ClearState();

            node.TokenManager.IssuedPushTokens.Clear();

            node.seenPackets.Clear();
            node.requestedBlocks.Clear();
            node.issuedTokens.Clear();

            node.isBootstrapped = false;

        }






    }
}
