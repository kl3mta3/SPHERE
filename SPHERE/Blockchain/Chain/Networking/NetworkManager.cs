using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using SPHERE.Blockchain;
using SPHERE.Configure;
using SPHERE.Configure.Logging;
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
                SystemLogger.Log("Debug-BrodcastConnectionToNetwork: Starting Broadcast Network Connection...");


                // Use RetryAsync to retry the operation on failure
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    SystemLogger.Log("Debug-BrodcastConnectionToNetwork: Broadcast  Network Connection packet...");
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
                    SystemLogger.Log($"Debug-BrodcastConnectionToNetwork: Packet built with NodeId: {node.Peer.NodeId}, IP: {node.Client.clientIP}, Port: {node.Client.clientListenerPort}");

                    // Serialize the packet into a byte array
                    SystemLogger.Log("Debug-BrodcastConnectionToNetwork: Serializing packet...");
                    byte[] data = Packet.PacketBuilder.SerializePacket(packet);
                    SystemLogger.Log($"Debug-BrodcastConnectionToNetwork: Packet serialized. Data Length: {data.Length} bytes");

                    bool allSuccessful = true;

                    List<Peer> peers = node.RoutingTable.GetAllPeers();

                    var tasks = peers.Select(async peer =>
                    {
                        SystemLogger.Log("Debug-BrodcastConnectionToNetwork: Encrypting packet...");

                        try
                        {
                            // Encrypt the packet using the recipient's public communication key
                            byte[] encryptedData = Encryption.EncryptPacketWithPublicKey(node, data, peer.PublicEncryptKey);
                            SystemLogger.Log($"Debug-BrodcastConnectionToNetwork: Packet encrypted. Encrypted Data Length: {encryptedData.Length} bytes");

                            // Send the encrypted data and signature to the recipient
                            SystemLogger.Log($"Debug-BrodcastConnectionToNetwork: Sending packet to NODE: {peer.NodeId.Substring(0, 6)} at {peer.NodeIP}:{peer.NodePort}...");
                            bool success = await Client.SendPacketToPeerAsync(node, peer.NodeIP, peer.NodePort, encryptedData);

                            if (!success)
                            {
                                SystemLogger.Log($"Debug-BrodcastConnectionToNetwork: Failed to send broadcast to {peer.NodeIP}:{peer.NodePort}");
                                allSuccessful = false;
                            }
                            else
                            {
                                SystemLogger.Log($"Debug-BrodcastConnectionToNetwork: Broadcast successfully sent to {peer.NodeIP}:{peer.NodePort}");
                            }
                        }
                        catch (Exception ex)
                        {
                            SystemLogger.Log($"Error broadcasting to {peer.NodeIP}:{peer.NodePort}: {ex.Message}");
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

                    SystemLogger.Log("Debug-BrodcastConnectionToNetwork: Bootstrap Request process completed.");
                    return allSuccessful;
                });

            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-BrodcastConnectionToNetwork: {ex.Message}");
                SystemLogger.Log($"BrodcastConnectionToNetwork: Debug Trace: {ex.StackTrace}");
                throw;
            }

        }

        //-----Pings-----\\

        //Ping a single peer. Returns True or false based on successful ping. 
        public async Task<bool> PingPeerAsync(Node node, Peer peer)
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
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(node, Encoding.UTF8.GetBytes("PingRequest")))
                };

                // Send the ping and wait for a response
                bool success = await Client.SendPacketToPeerAsync(
                    node,
                    peer.NodeIP,
                    peer.NodePort,
                    Encoding.UTF8.GetBytes(pingPacket.Content)


                );

                return success; // Return true if the ping was successful
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error pinging peer {peer.NodeId}: {ex.Message}");
                return false; // Return false if there was an error
            }
        }

        // Send response to a Ping request.
        public async Task PongPeerAsync(Node node, Packet packet)
        {

            try
            {
                // Validate the incoming packet
                if (packet == null || packet.Header == null)
                {
                    SystemLogger.Log("Invalid ping request packet.");
                    return;
                }

                string senderIPAddress = packet.Header.IPAddress;
                int senderPort = int.Parse(packet.Header.Port);
                byte[] senderPublicSignatureKey = packet.Header.PublicSignatureKey;
                byte[] senderPublicEncryptKey = packet.Header.PublicEncryptKey;

                if (string.IsNullOrWhiteSpace(senderIPAddress) || string.IsNullOrWhiteSpace(Convert.ToBase64String(senderPublicSignatureKey)))
                {
                    SystemLogger.Log("Invalid ping request header details.");
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
                    SystemLogger.Log($"Added or updated peer {newPeer.NodeId} in the routing table.");
                }

                // Build the ping response packet
                Packet responsePacket = new Packet
                {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = node.Peer.NodeId,
                        IPAddress = node.Client.clientIP.ToString(),
                        Port = node.Client.clientListenerPort.ToString(),
                        PublicSignatureKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeSignatureKey),
                        PublicEncryptKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey),
                        Packet_Type = "Pong",
                        TTL = "1"
                    },
                    Content = Convert.ToBase64String(Encoding.UTF8.GetBytes("Pong")),
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(node, Encoding.UTF8.GetBytes("Pong")))
                };

                // Serialize and send the response packet
                byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(
                    node,
                    Encoding.UTF8.GetBytes(responsePacket.Content),
                    node.Peer.PublicEncryptKey

                );
                await RetryAsync<bool>(async () =>
                {
                    bool success = await Client.SendPacketToPeerAsync(node, senderIPAddress, senderPort, encryptedResponseData);

                    if (success)
                    {
                        SystemLogger.Log($"Successfully sent PingResponse to {senderIPAddress}:{senderPort}");
                        return success;
                    }
                    else
                    {
                        SystemLogger.Log($"Failed to send PingResponse to {senderIPAddress}:{senderPort}");
                        return success;
                    }
                });
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error responding to ping: {ex.Message}");
            }
        }

        //Process Pong Response.
        public  Task ProcessPongAsync(Node node, Packet packet)
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
                        SystemLogger.Log($"Error: Invalid peer received in Pong request.");
                        return Task.CompletedTask;
                    }
                }


                node.RoutingTable.UpdatePeer(peer);
               NetworkManager.BroadcastReputationUpdate(node, peer, Blockchain.Reputation.ReputationReason.GetContactFailed);

            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error: Failure processing Pong Request:{ex.Message}");
            }
            return Task.CompletedTask;
        }

        //Send PingPal Request.
        public async Task<bool> PingPalAsync(Node node, Peer peer)
        {
            try
            {

                Packet responsePacket = new Packet
                {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = node.Peer.NodeId,
                        IPAddress = node.Client.clientIP.ToString(),
                        Port = node.Client.clientListenerPort.ToString(),
                        PublicSignatureKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeSignatureKey),
                        PublicEncryptKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey),
                        Packet_Type = Packet.PacketBuilder.PacketType.PingPal.ToString(),
                        TTL = "1"
                    },
                    Content = Convert.ToBase64String(Encoding.UTF8.GetBytes("PingPal")),
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(node, Encoding.UTF8.GetBytes("PingPal")))
                };

                byte[] data = Packet.PacketBuilder.SerializePacket(responsePacket);

                byte[] encryptedData = Encryption.EncryptPacketWithPublicKey(node, data, peer.PublicEncryptKey);

                // Send the ping and wait for a response
                bool success = await Client.SendPacketToPeerAsync(
                    node,
                    peer.NodeIP,
                    peer.NodePort,
                    encryptedData
                );

                if (!success)
                {
                    SystemLogger.Log($"Failed to send PingPal to {peer.NodeId}");
                    return false;
                }
                else
                {
                    SystemLogger.Log($"Successfully sent PingPal to {peer.NodeId}");
                    return success;
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error pinging peer {peer.NodeId}: {ex.Message}");
                return false; 
            }
        }

        //Send PongPal Response.
        public async Task RespondToPingPalAsync(Node node, Packet packet)
        {

            try
            {
                Peer senderPeer= Peer.CreatePeerFromPacket(packet);

                // Validate the incoming packet
                if (packet == null || packet.Header == null || senderPeer == null)
                {
                    SystemLogger.Log("Invalid pong pal request packet.");
                    return;
                }

                string senderIPAddress = packet.Header.IPAddress;
                int senderPort = int.Parse(packet.Header.Port);
                byte[] senderPublicSignatureKey = packet.Header.PublicSignatureKey;
                byte[] senderPublicEncryptKey = packet.Header.PublicEncryptKey;

                if (string.IsNullOrWhiteSpace(senderIPAddress) || string.IsNullOrWhiteSpace(Convert.ToBase64String(senderPublicSignatureKey)))
                {
                    SystemLogger.Log("Invalid ping request header details.");
                    return;
                }

                // Validate and potentially add the sender to the routing table
                lock (node.RoutingTable)
                { 

                    // Add the peer to the RoutingTable (handles duplicates and updates)
                    node.RoutingTable.AddPeer(senderPeer);
                    SystemLogger.Log($"Added or updated peer {senderPeer.NodeId} in the routing table.");
                }

              
                    // Build the ping response packet
                    Packet responsePacket = new Packet
                    {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = node.Peer.NodeId,
                        IPAddress = node.Client.clientIP.ToString(),
                        Port = node.Client.clientListenerPort.ToString(),
                        PublicSignatureKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeSignatureKey),
                        PublicEncryptKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey),
                        Packet_Type = Packet.PacketBuilder.PacketType.PongPal.ToString(),
                        TTL = "1"
                    },
                    Content = Convert.ToBase64String(Encoding.UTF8.GetBytes("PongPal")),
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(node, Encoding.UTF8.GetBytes("Pong")))
                };

                // Serialize and send the response packet
                byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(node,
                    Encoding.UTF8.GetBytes("PongPal"),
                    node.Peer.PublicEncryptKey

                );

                if (!node.TokenManager.pingPals.ContainsKey(senderPeer))
                {
                    
                    await node.NetworkManager.RetryAsync<bool>(async () =>
                    {
                        node.TokenManager.pingPals.Add(senderPeer, DateTime.UtcNow);

                        bool success = await Client.SendPacketToPeerAsync(node, senderIPAddress, senderPort, encryptedResponseData);

                        if (success)
                        {
                            SystemLogger.Log($"Successfully sent PingResponse to {senderIPAddress}:{senderPort}");
                            return success; 
                        }
                        else
                        {
                            SystemLogger.Log($"Failed to send PingResponse to {senderIPAddress}:{senderPort}");
                            return success;
                        }
                    });
                }
                else
                {
                    bool success = false;
                    await node.NetworkManager.RetryAsync<bool>(async () =>
                    {
                        DateTime lastPing = node.TokenManager.pingPals[senderPeer];
                        if (DateTime.UtcNow - lastPing > TimeSpan.FromHours(24))
                        {
                            node.TokenManager.pingPals.Remove(senderPeer);
                            TokenManager.PushToken token = node.TokenManager.CreatePushToken(node, senderPeer.NodeId);
                            await node.NetworkManager.SendTokenToPeer(node, senderPeer, token);
                            node.TokenManager.AddIssuedPushToken(token); 
                        }
                        return success;
                    });

                }
               
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error responding to ping: {ex.Message}");
            }
        }

        //Process PongPal Response.
        public static Task PongPalProcess(Node node, Packet packet)
        {
            Peer peer = Peer.CreatePeerFromPacket(packet);
            node.TokenManager.pingPal = peer;
            return Task.CompletedTask;
        }

        //Send a Push Token Extend Ping to the receiver.
        //The receiver will then send a Push Token Extend Pong to us that includes the original Token as proof or a Failed pong if they can not.
        public static  Task SendPushTokenExtendPing(Node node, string tokenId, string receiverId)
        {

            //look up the receiver in the routing table.
            Peer receiver = node.RoutingTable.GetPeerByID(receiverId);
            if (receiver == null)
            {
                SystemLogger.Log("Receiver not found in routing table.");
                return Task.CompletedTask;
            }
            //we will send a push token extend ping to the receiver.
            //They will then send a push token extend pong to us that includes the original Token as proof or a Failed pong if they can not.
            return Task.CompletedTask;
        }

        //Process a Push Token Extend Pong.
        public static async Task ProcessPushTokenExtendPing(Node node, Packet packet)
        {
            try
            {
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid PushTokenExtendPong packet.");
                    return ;
                }

                Peer senderPeer = Peer.CreatePeerFromPacket(packet);

                if (senderPeer == null)
                {
                    SystemLogger.Log("Received an invalid PushTokenExtendPong packet.");
                    return ;
                }

                // Deserialize the payload
                string tokenId = JsonSerializer.Deserialize<string>(packet.Content);

                if (string.IsNullOrWhiteSpace(tokenId))
                {
                    SystemLogger.Log("Received an empty or invalid PushTokenExtendPong payload.");
                    return ;
                }

                TokenManager.PushToken token = node.TokenManager.GetToken(tokenId);
                var serilizedToken = JsonSerializer.Serialize<TokenManager.PushToken>(token);
                Packet responsePacket = new Packet
                {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = node.Peer.NodeId,
                        IPAddress = node.Client.clientIP.ToString(),
                        Port = node.Client.clientListenerPort.ToString(),
                        PublicSignatureKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeSignatureKey),
                        PublicEncryptKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey),
                        Packet_Type = Packet.PacketBuilder.PacketType.PongPal.ToString(),
                        TTL = "1"
                    },
                    Content = serilizedToken,
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(node, Encoding.UTF8.GetBytes("Pong")))
                };

                byte[] bytes = Packet.PacketBuilder.SerializePacket(responsePacket);
                byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(node, bytes, senderPeer.PublicEncryptKey);

                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                   bool success= await Client.SendPacketToPeerAsync(node, senderPeer.NodeIP, senderPeer.NodePort, encryptedResponseData);

                    if (success)
                        {
                        SystemLogger.Log($"Successfully sent PushTokenExtendPong to {senderPeer.NodeId}");
                        return success;
                    }
                    else
                    {
                        SystemLogger.Log($"Failed to send PushTokenExtendPong to {senderPeer.NodeId}");
                        return success;
                    }
                });
                  

            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing PushTokenExtendPong: {ex.Message}");
            }
            return;
        }


        //Process a Push Token Extend Pong.
        public static Task ProcessPushTokenExtendPong(Node node, Packet packet)
        {
            try
            {
                Peer peer = Peer.CreatePeerFromPacket(packet);
                if (node == null || packet == null || peer == null)
                {
                    SystemLogger.Log("Error: Invalid PushTokenExtendPong packet.");
                    return Task.CompletedTask;
                }

                TokenManager.PushToken token = JsonSerializer.Deserialize<TokenManager.PushToken>(packet.Content);
                if (token == null || !node.TokenManager.IssuedPushTokens.ContainsKey(token.IssuerId))
                {
                    SystemLogger.Log("Error: Invalid PushTokenExtendPong payload.");
                    return Task.CompletedTask;
                }
                if (SignatureGenerator.VerifyIssuedPushToken(node, token))
                {

                    var storedToken = node.TokenManager.IssuedPushTokens[token.IssuerId];
                    storedToken.Timestamp = DateTime.UtcNow;
                    node.TokenManager.IssuedPushTokens[token.IssuerId] = storedToken;
                }
                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing PushTokenExtendPong: {ex.Message}");
                return Task.CompletedTask;
            }
        }

        //-----Peers-----\\

        //Send Peer List to requesting peer.
        public async Task PeerListResponse(Node node, Packet packet)
        {

            try
            {
                SystemLogger.Log("Debug-PeerListResponse: Starting to send bootstrap response...");
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

                SystemLogger.Log($"Debug-PeerListResponse: Recipient details - NodeId: {recipientsID}, IP: {recipientIPAddress}, Port: {recipientPort}, PublicComKey: {recipientPublicEncryptKey}");

                // Validate inputs
                if (packet == null)
                {
                    SystemLogger.Log("Debug-PeerListResponse: Packet is null.");
                    throw new ArgumentNullException(nameof(packet), "Packet cannot be null.");
                }

                if (node == null)
                {
                    SystemLogger.Log("Debug-PeerListResponse: Node is null.");
                    throw new ArgumentNullException(nameof(node), "The Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(recipientIPAddress))
                {
                    SystemLogger.Log("Debug-PeerListResponse: Recipient IP address is invalid.");
                    throw new ArgumentException("Packet's IP address cannot be null or empty.", nameof(recipientIPAddress));
                }

                if (recipientPort <= 0 || recipientPort > 65535)
                {
                    SystemLogger.Log($"Debug-PeerListResponse: Invalid recipient port: {recipientPort}");
                    throw new ArgumentOutOfRangeException(nameof(recipientPort), "Packet port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(Convert.ToBase64String(recipientPublicEncryptKey)))
                {
                    SystemLogger.Log("Debug-PeerListResponse: Recipient's public encryption key is invalid.");
                    throw new ArgumentException("Recipient's public encryption key cannot be null or empty.", nameof(recipientPublicEncryptKey));
                }

                SystemLogger.Log("Debug-PeerListResponse: Inputs validated successfully.");

                // Use RetryAsync to ensure the response is sent
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    SystemLogger.Log("Debug-PeerListResponse: Preparing peer list for response...");
                    List<Peer> peerList;

                    lock (node.RoutingTable)
                    {
                        if (!string.IsNullOrWhiteSpace(recipientsID))
                        {
                            peerList = node.RoutingTable.GetClosestPeers(recipientsID, 20); // Adjust '20' as needed
                            SystemLogger.Log($"Debug-PeerListResponse: Retrieved {peerList.Count} closest peers for NodeId {recipientsID}.");
                        }
                        else
                        {
                            peerList = node.RoutingTable.GetAllPeers();
                            SystemLogger.Log($"Debug-PeerListResponse: Retrieved all peers. Total: {peerList.Count}");
                        }
                    }

                    SystemLogger.Log($"Debug-PeerListResponse: Peer list prepared. Count: {peerList.Count}");


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

                    SystemLogger.Log("Debug-PeerListResponse: Serializing response payload...");
                    byte[] responseData = Packet.PacketBuilder.SerializePacket(responsePacket);
                    SystemLogger.Log($"Debug-PeerListResponse: Serialized response payload. Size: {responseData.Length} bytes");
                    bool success = new bool();

                    // Encrypt the response data using the recipient's public communication key
                    SystemLogger.Log("Debug-PeerListResponse: Encrypting response data...");



                    byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(node, responseData, recipientPublicEncryptKey);

                    // Send the encrypted response data and signature to the recipient
                    SystemLogger.Log($"Debug-PeerListResponse: Sending response to {recipientIPAddress}:{recipientPort}...");
                    success = await Client.SendPacketToPeerAsync(node, recipientIPAddress, recipientPort, encryptedResponseData);



                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        SystemLogger.Log($"Debug-PeerListResponse: Failed to send Peer List Response to {recipientIPAddress}:{recipientPort}");
                        throw new Exception($"PeerListResponse: Failed to send Peer List Response to {recipientIPAddress}:{recipientPort}.");
                    }

                    // Reward the recipient with a trust score for a valid request
                    SystemLogger.Log("Debug-PeerListResponse: Updating trust score for recipient...");
                    lock (node.RoutingTable)
                    {
                        var peer = node.RoutingTable.GetPeerByIPAddress(recipientIPAddress);
                        if (peer != null)
                        {
                            NetworkManager.BroadcastReputationUpdate(node, peer, Blockchain.Reputation.ReputationReason.GetContactFailed);
                            SystemLogger.Log($"Debug-PeerListResponse: Trust score updated for peer {peer.NodeId}. New Trust Score: {peer.Reputation}");
                        }
                        else
                        {
                            SystemLogger.Log("Debug-PeerListResponse: Recipient peer not found in the routing table.");
                        }
                    }

                    // Log successful bootstrap response
                    SystemLogger.Log($"Debug-PeerListResponse: Peer List Response successfully sent to {recipientIPAddress}:{recipientPort}.");

                    await node.Client.BroadcastToPeerList(node, packet);
                    return success; // Explicitly return success

                });

                SystemLogger.Log("Debug-PeerListResponse: Peer List Response process completed successfully.");
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error-PeerListResponse: {ex.Message}");
                SystemLogger.Log($"PeerListResponse: Debug Trace: {ex.StackTrace}");
                throw;
            }


        }
        
        //Send a Push Token to a peer.
        internal async Task SendTokenToPeer(Node node, Peer peer, TokenManager.PushToken token)
        {
            await node.NetworkManager.RetryAsync<bool>(async () =>
            {
                // Build GetResponse packet
                var responseHeader = Packet.PacketBuilder.BuildPacketHeader(
                Packet.PacketBuilder.PacketType.PushTokenIssued,
                node.Peer.NodeId,
                node.Peer.Node_Type.ToString(),
                node.Peer.PublicSignatureKey,
                node.Peer.PublicEncryptKey,
                node.Client.clientListenerPort,
                node.Client.clientIP.ToString(),
                1
                );

                var responsePacket = Packet.PacketBuilder.BuildPacket(responseHeader, JsonSerializer.Serialize(token));
                byte[] serializedResponse = Packet.PacketBuilder.SerializePacket(responsePacket);

                // Encrypt with the requester's public key
                byte[] encryptedResponse = Encryption.EncryptPacketWithPublicKey(node, serializedResponse, peer.PublicEncryptKey);

                // Send the response to the requester
                bool success = await Client.SendPacketToPeerAsync(node, peer.NodeIP, peer.NodePort, encryptedResponse);

                if (success)
                    SystemLogger.Log($"Successfully sent PushToken to {peer.NodeIP}:{peer.NodePort}");
                else
                    SystemLogger.Log($"Failed to send PushToken to {peer.NodeIP}:{peer.NodePort}");

                return success;
            });
        }

        //Process a Push Token Issued packet.
        internal static Task ProcessIssuedToken(Node node, Packet packet)
        {
            try
            {
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid PushTokenIssued packet.");
                    return Task.CompletedTask;
                }

                Peer senderPeer = Peer.CreatePeerFromPacket(packet);

                if (senderPeer == null)
                {
                    SystemLogger.Log("Received an invalid PushTokenIssued packet.");
                    return Task.CompletedTask;
                }

                // Deserialize the payload
                TokenManager.PushToken token = JsonSerializer.Deserialize<TokenManager.PushToken>(packet.Content);

                if (token == null || string.IsNullOrWhiteSpace(token.TokenId))
                {
                    SystemLogger.Log("Received an empty or invalid PushTokenIssued payload.");
                    return Task.CompletedTask;
                }

                // Add the token to the Issued Tokens
                node.TokenManager.AddReceivedPushToken(node, token, senderPeer.PublicSignatureKey);


            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing PushTokenIssued: {ex.Message}");
            }
            return Task.CompletedTask;
        }


        //-----Node Get Calls-----\\

        /// <summary>
        /// Get calls are used to request a block from the network.
        /// The request is sent to the closest peer (in terms of node ID distance) to the desired block.
        /// If the receiving node has the block, it sends the block back to the requester.
        /// If the block is not available locally, the node will forward (rebroadcast) the request
        /// to the closest peer it knows of to the target block.
        /// Leveraging Kademlia's routing algorithm, any block in the network can be reached in O(log n) hops,
        /// ensuring efficient retrieval even in large distributed networks.
        /// Example:
        /// _____________________________________________________________________________________
        /// | Total Nodes (n)	Redundancy (k)	Max Hops (log₂ n)   Avg Hops (with redundancy)   |
        /// |____________________________________________________________________________________|
        /// | 1,000,000  	 |      20	       |   ~20	          |  12-16                       |
        /// | 2,000,000	     |      20         |   ~21	          |  13-17                       |
        /// | 10,000,000	 |      20         |   ~24	          |  15-20                       |
        /// |____________________________________________________________________________________|
        /// </summary>

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
                    SystemLogger.Log("Block already exists locally.");
                    return;

                }

                //We add it to requested blocks.  So we can only add GetResponses in requestedBlocks.
                if (!node.requestedBlocks.TryAdd(blockId, DateTime.UtcNow))
                {
                    SystemLogger.Log($"Block {blockId} is already requested. Skipping redundant request.");
                    return;
                }

                // Get the closest peers to request the block from
                List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(blockId, 5);
                if (closestPeers.Count == 0)
                {
                    SystemLogger.Log("No peers available to request the block from.");
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
                    SystemLogger.Log($"Sending block request to peer: {peer.NodeIP}:{peer.NodePort}");

                    try
                    {

                        byte[] encryptedPacket = Encryption.EncryptPacketWithPublicKey(node, serializedPacket, peer.PublicEncryptKey);


                        bool success = await Client.SendPacketToPeerAsync(node, peer.NodeIP, peer.NodePort, encryptedPacket);

                        if (!success)
                        {
                            SystemLogger.Log($"Failed to request block {blockId} from {peer.NodeIP}:{peer.NodePort}");

                        }
                    }
                    catch (Exception ex)
                    {
                        SystemLogger.Log($"Error sending request to {peer.NodeIP}:{peer.NodePort}: {ex.Message}");
                    }
                });

                // Execute all requests in parallel
                await Task.WhenAll(tasks);

            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error requesting block: {ex.Message}");

            }

        }

        //Respond to a GetRequest.
        public async Task RespondToGetRequest(Node node, Packet packet)
        {

            try
            {

                if (packet == null || packet.Header == null)
                {
                    SystemLogger.Log("Received an invalid GetRequest packet.");
                    return;
                }

                if (!int.TryParse(packet.Header.TTL, out int ttlValue) || ttlValue <= 0)
                {
                    SystemLogger.Log("Invalid or expired TTL. Dropping request.");
                    return;
                }

                int newTTL = ttlValue - 1;

                var requestedBlockIds = JsonSerializer.Deserialize<List<string>>(packet.Content);

                SystemLogger.Log($"Received GetRequest for Block ID: {requestedBlockIds}");


                List<Block> requestedBlocks = new List<Block>();
                List<string> notFoundBlocks = new List<string>();


                //  Check if we already have the requested block
                foreach (var blockId in requestedBlockIds)
                {
                    Block block = node.ContactDHT.GetBlock(blockId);

                    if (block != null)
                    {
                        SystemLogger.Log($"Block {blockId} found locally. Adding to response list.");
                        requestedBlocks.Add(block);
                    }
                    else
                    {
                        SystemLogger.Log($"Block {blockId} not found locally. Adding to not found list.");
                        notFoundBlocks.Add(blockId);
                    }
                }


                if (requestedBlocks.Count > 0)
                {
                    await node.NetworkManager.RetryAsync<bool>(async () =>
                    {
                        SystemLogger.Log($"Block {requestedBlockIds.Count} found locally. Sending GetResponse to requester...");

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
                        byte[] encryptedResponse = Encryption.EncryptPacketWithPublicKey(node, serializedResponse, packet.Header.PublicEncryptKey);

                        // Send the response to the requester
                        bool success = await Client.SendPacketToPeerAsync(node, packet.Header.IPAddress, int.Parse(packet.Header.Port), encryptedResponse);
                        if (success)
                            SystemLogger.Log($"Successfully sent GetResponse for {requestedBlockIds.Count} Blocks to {packet.Header.IPAddress}:{packet.Header.Port}");
                        else
                            SystemLogger.Log($"Failed to send GetResponse for {requestedBlockIds} Blocks to {packet.Header.IPAddress}:{packet.Header.Port}");

                        return success;
                    });
                 }
                    // Block not found, rebroadcast the request to the closest peers
                    SystemLogger.Log($"Blocks not found locally. Rebroadcasting request to peers...");

                bool success = false;
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    foreach (var Ids in notFoundBlocks)
                    {   
                    
                        // Get closest peers
                        List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(Ids, 5);
                        if (closestPeers.Count == 0)
                        {
                            SystemLogger.Log("No peers available to forward the request.");
                            continue;
                        }

                        packet.Header.TTL = newTTL.ToString();

                        byte[] serializedPacket = Packet.PacketBuilder.SerializePacket(packet);

                        var tasks = closestPeers.Select(async peer =>
                        {
                            SystemLogger.Log($"Forwarding GetRequest for Block {Ids} to {peer.NodeIP}:{peer.NodePort}");

                            try
                            {
                                byte[] encryptedPacket = Encryption.EncryptPacketWithPublicKey(node, serializedPacket, peer.PublicEncryptKey);
                                 success = await Client.SendPacketToPeerAsync(node, peer.NodeIP, peer.NodePort, encryptedPacket);
                            }
                            catch (Exception ex)
                            {
                                SystemLogger.Log($"Error forwarding GetRequest to {peer.NodeIP}:{peer.NodePort}: {ex.Message}");
                            }
                        });
                        await Task.WhenAll(tasks); 
                    }
                        return success;
                });
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing GetRequest: {ex.Message}");
            }

        }

        //Process GetResponse.
        public async Task ProcessGetResponse(Node node, Packet packet)
        {
            

            try
            {
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid GetResponse packet.");
                    return;
                }

                // Deserialize the payload
                BlockResponsePayload payload = JsonSerializer.Deserialize<BlockResponsePayload>(packet.Content);

                if (payload == null || payload.Blocks == null || payload.Blocks.Count == 0)
                {
                    SystemLogger.Log("Received an empty or invalid GetResponse payload.");
                    return;
                }

                // Process each block in the response
                foreach (var block in payload.Blocks)
                {
                    if (block == null || string.IsNullOrWhiteSpace(block.Header.BlockId))
                    {
                        SystemLogger.Log("Received an invalid block in GetResponse.");
                        continue;
                    }

                    // Check if the block is already requested
                    if (!node.requestedBlocks.ContainsKey(block.Header.BlockId))
                    {
                        SystemLogger.Log($"Block {block.Header.BlockId} was not requested. Ignoring.");
                        continue;
                    }

                    // Add the block to the DHT
                    node.ContactDHT.AddBlock(block);

                    // Remove the block from the requested list
                    node.requestedBlocks.TryRemove(block.Header.BlockId, out _);

                    SystemLogger.Log($"Successfully added block {block.Header.BlockId} to the DHT.");
                }

                //Reward the sender with a Reputation Score and a Token
               Peer senderPeer= Peer.CreatePeerFromPacket(packet);

                if (senderPeer != null)
                {
                    TokenManager.PushToken token = node.TokenManager.CreatePushToken(node, senderPeer.NodeId);
                    await node.NetworkManager.SendTokenToPeer(node, senderPeer, token);
                    node.TokenManager.AddIssuedPushToken(token);

                    BroadcastReputationUpdate(node, senderPeer, Blockchain.Reputation.ReputationReason.GetContactFailed);
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing GetResponse: {ex.Message}");
            }
        }


        //-----Node Put Calls-----\\

        /// <summary>
        /// Put Calls are to broadcast a block to the network.
        /// A node can not do this it self. If a node wants to add a block to the network it must use a token that will have been provided from another node for work done.
        /// The block and the token must be sent to the peer that issued the token. The peer will then broadcast the block to the network after verifying the token and block.
        /// </summary>
       
        //Broadcast a Put request to the network if the included Token was issued by this node and is valid.
        internal static async  Task VerifyAndBroadcastPutRequest(Node node, Packet packet)
        {
            try
            {

                if (node == null)
                {
                    SystemLogger.Log($"{nameof(node)}, Node cannot be null.");
                    return;
                }
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid PutRequest packet.");
                    return;
                }

                Peer requestingPeer = Peer.CreatePeerFromPacket(packet);
                PutRequestPayload payload = JsonSerializer.Deserialize<PutRequestPayload>(packet.Content);
                Block block= payload.Block;
                TokenManager.PushToken token = payload.Token;

                if (block == null)
                {
                    SystemLogger.Log($"{nameof(block)}, Block cannot be null.");
                    return;
                }

                if (token == null || !SignatureGenerator.VerifyIssuedPushToken(node, token))
                {
                    SystemLogger.Log($"{nameof(token)}, Reputation cannot be null.");
                    return;
                }


                    // Build a PutRequest packet
                    var header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.PutRequest,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        50 // TTL value
                    );

                    Packet putPacket = Packet.PacketBuilder.BuildPacket(header, JsonSerializer.Serialize(block));
                 
       
                    SystemLogger.Log($"Sending PutRequest to peerlist");

                try
                {
                   bool success = await node.Client.BroadcastToPeerList(node, putPacket);

                    if (success)
                    {
                        SystemLogger.Log($"Successfully sent PutRequest to peer list.");
                        node.TokenManager.CashOutIssuedToken(node, token);
                    }
                    else
                    {
                        SystemLogger.Log($"Failed to send PutRequest to peer list.");
                    }
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Error sending PutRequest to peer list {ex.Message}");
                }
        
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error broadcasting PutRequest: {ex.Message}");
            }
            return;
        }

        //Request a block be Put into the network by a peer providing back a token the node was issued.
        internal static async Task<bool> RequestPutWithToken(Node node, Block block, TokenManager.PushToken token)
        {
            try
            {
                if (node == null)
                {
                    SystemLogger.Log($"Error:-RequestPutWithToken: {nameof(node)}, Node cannot be null.");
                    return false;
                }

                if (block == null)
                {
                    SystemLogger.Log($"Error:-RequestPutWithToken: {nameof(block)}, Block cannot be null.");
                    return false;
                }

                Peer tokenIssuingPeer = node.RoutingTable.GetPeerByID(token.IssuerId);

                if (tokenIssuingPeer == null)
                {
                    SystemLogger.Log("Error:-RequestPutWithTokenToken: Issuer not in peer list.");
                    return false;
                }

                if (token == null || !SignatureGenerator.VerifyReceivedPushToken(node, token, tokenIssuingPeer.PublicSignatureKey))
                {
                    SystemLogger.Log($"Error:-RequestPutWithToken: {nameof(token)}, Token is not valid.");
                    return false;
                }

                // Build a PutRequest packet
                var header = Packet.PacketBuilder.BuildPacketHeader(
                    Packet.PacketBuilder.PacketType.PutRequest,
                    node.Peer.NodeId,
                    node.Peer.Node_Type.ToString(),
                    node.Peer.PublicSignatureKey,
                    node.Peer.PublicEncryptKey,
                    node.Client.clientListenerPort,
                    node.Client.clientIP.ToString(),
                    1 // TTL value
                );

                PutRequestPayload payload = new PutRequestPayload
                {
                    Block = block,
                    Token = token
                };

                
                Packet putPacket = Packet.PacketBuilder.BuildPacket(header, JsonSerializer.Serialize<PutRequestPayload>(payload));

                SystemLogger.Log($"Error:-RequestPutWithToken: Sending PutRequest to peerlist");

                bool success = await node.Client.BroadcastToPeerList(node, putPacket);

                if (success)
                {
                    SystemLogger.Log($"Error:-RequestPutWithToken: Successfully sent PutRequest to peer list.");
                    node.TokenManager.CashOutIssuedToken(node, token);
                }
                else
                {
                    SystemLogger.Log($"Error:-RequestPutWithToken: Failed to send PutRequest to peer list.");
                }

                return success;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error:-RequestPutWithToken: Error broadcasting PutRequest: {ex.Message}");
                return false;
            }
        }

        //Process a Put Request adding the Block if its within the range of the node and rebroadcasting the request.
        internal static async Task ProcessIncomingVerifiedPutRequest(Node node, Packet packet)
        {
            try
            {
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid PutRequest packet.");
                    return;
                }

                // Deserialize the payload
                Block block = JsonSerializer.Deserialize<Block>(packet.Content);

                if (block == null || string.IsNullOrWhiteSpace(block.Header.BlockId))
                {
                    SystemLogger.Log("Received an empty or invalid PutRequest payload.");
                    return;
                }

                // Check if the block is already in the DHT
                if (node.ContactDHT.GetBlock(block.Header.BlockId) != null)
                {
                    SystemLogger.Log($"Block {block.Header.BlockId} already exists locally. Ignoring PutRequest.");

                }
                else
                {
                    // Check if the block is within the range of the node
                    if (node.ContactDHT.ShouldStoreBlock(node, block.Header.BlockId, node.RoutingTable.replicationFactor))
                    {
                         // Add the block to the DHT
                        SystemLogger.Log($"Block {block.Header.BlockId} is within the range of the node. Adding Block.");
                        node.ContactDHT.AddBlock(block);
                    }
                    else
                    {
                        SystemLogger.Log($"Block {block.Header.BlockId} is not within the range of the node. Ignoring PutRequest.");

                    }

                }
                // Rebroadcast the PutRequest to the closest peers
                List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(block.Header.BlockId, 5);
                if (closestPeers.Count == 0)
                {
                    SystemLogger.Log("No peers available to forward the request.");
                    return;
                }
                SystemLogger.Log($"Sending PutRequest to peerlist");

                try
                {
                    bool success = await node.Client.BroadcastToPeerList(node, packet);

                    if (success)
                    {
                        SystemLogger.Log($"Successfully sent PutRequest to peer list.");
                    }
                    else
                    {
                        SystemLogger.Log($"Failed to send PutRequest to peer list.");
                    }
                }
                catch (Exception)
                {
                    SystemLogger.Log($"Error sending PutRequest to peer list.");
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing PutRequest: {ex.Message}");
            }
        }


        //-----Reputation Management-----\\

        //Send a Reputation Update to network
        public static Task BroadcastReputationUpdate(Node node, Peer peer, Reputation.ReputationReason reason)
        {
            if (node.Peer==peer)
            {
                SystemLogger.Log("Error-BroadcastReputationUpdate: Cannot send a Reputation Update to self.");
                return Task.CompletedTask;
            }

            if (node !=null && Peer.ValidatePeer(peer) )
            {
               
                try
                {
                    Reputation reputation = new();
                    reputation.CreateReputation(node, peer.NodeId, reason);

                    string content = JsonSerializer.Serialize(reputation);

                    // Build the ReputationUpdate packet
                    Packet responsePacket = new Packet
                    {
                        Header = new Packet.PacketHeader
                        {
                            NodeId = node.Peer.NodeId,
                            IPAddress = node.Client.clientIP.ToString(),
                            Port = node.Client.clientListenerPort.ToString(),
                            PublicSignatureKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeSignatureKey),
                            PublicEncryptKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey),
                            Packet_Type = Packet.PacketBuilder.PacketType.ReputationUpdate.ToString(),
                            TTL = "1"
                        },
                        Content = content,
                        Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(node, Convert.FromBase64String(content))),
                    };

                    // Send the response to the requester
                    node.Client.BroadcastToPeerList(node, responsePacket);


                    SystemLogger.Log($"Successfully sent ReputationUpdate to {peer.NodeIP}:{peer.NodePort}");
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Error sending ReputationUpdate: {ex.Message}");
                }
            }
            return Task.CompletedTask;
        }

        //Process a Reputation Update.
        internal static async Task ProcessReputationUpdate(Node node, Packet packet)
        {
            try
            {
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid ReputationUpdate packet.");
                    return;
                }
                Peer senderPeer = Peer.CreatePeerFromPacket(packet);

                if(senderPeer == null)
                {
                    SystemLogger.Log("Received an invalid ReputationUpdate packet.");
                    return;
                }


                // Deserialize the payload
                var reputation = JsonSerializer.Deserialize<Reputation>(packet.Content);

                if (reputation == null || string.IsNullOrWhiteSpace(reputation.UpdateIssuedByNodeId) || string.IsNullOrWhiteSpace(reputation.NodeId))
                {
                    SystemLogger.Log("Received an empty or invalid ReputationUpdate payload.");
                    return;
                }

                if(!Reputation.ShouldAcceptReputationUpdate(node, packet))
                {
                    SystemLogger.Log("Reputation updated too recently from same peer for same reason.");
                    return;

                }


                // Validate the signature
                byte[] signature = Convert.FromBase64String(packet.Signature);
                byte[] content = Encoding.UTF8.GetBytes(packet.Content);

                if (!SignatureGenerator.VerifyByteArray(content, signature, senderPeer.PublicSignatureKey))
                {
                    SystemLogger.Log("Invalid signature on ReputationUpdate packet.");
                    return;
                }

                //Check is we have the Reputation Block in the ReputationDHT.
                Block block = node.ReputationDHT.GetBlock(reputation.UpdateIssuedByNodeId);
                Reputation newReputation = Reputation.UpdatedReputation(node, reputation, reputation.UpdateIssuedByNodeId, Reputation.GetReputationReasonFromString(reputation.Reason));

                if (block != null)
                {
                    // Add the reputation to the Reputation DHT

                    block.ReputationBlock = JsonSerializer.Serialize(newReputation);
                }
                else
                {

                    SystemLogger.Log("Reputation Block not found in the Reputation DHT.");
                   // Add the reputation to the Reputation DHT
                    if (node.ReputationDHT.ShouldStoreBlock(node, reputation.NodeId, node.RoutingTable.replicationFactor))
                    { 
                        Reputation.ReputationReason reason= Reputation.GetReputationReasonFromString(reputation.Reason);
                        string serialiszedNewReputation = JsonSerializer.Serialize(newReputation);
                        Block newBlock = Block.CreateReputationBlock(
                            node,
                            "UNKNOWN",
                            serialiszedNewReputation,
                            EncryptionAlgorithm.AES256
                            );
                        node.ReputationDHT.AddBlock(newBlock);


                    }
                }
           

                bool success=false;
                // Use RetryAsync to retry the operation on failure
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    await node.Client.BroadcastToPeerList(node, packet);
                     return success;
                });


                // Update the reputation score
                Peer receiver = node.RoutingTable.GetPeerByID(reputation.NodeId);

                if (receiver != null)
                {
                    receiver.Reputation += reputation.ReputationChange;
                    SystemLogger.Log($"Reputation updated for {receiver.NodeId}. New score: {receiver.Reputation}");
                }
                else
                {
                    SystemLogger.Log($"Peer {reputation.NodeId} not found in the routing table.");
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing ReputationUpdate: {ex.Message}");
            }
        }

        //Process a Reputation Request.
        public async Task ReturnRequestedReputation(Node node, Packet packet)
        {
            try
            {
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid ReputationRequest packet.");
                    return;
                }

                // Deserialize the payload
                string requestedNodeId = packet.Content;

                if (string.IsNullOrWhiteSpace(requestedNodeId))
                {
                    SystemLogger.Log("Received an empty or invalid ReputationRequest payload.");
                    return;
                }

                // Check if we have the requested reputation
                Block block = node.ReputationDHT.GetBlock(requestedNodeId);

                if (block == null)
                {
                    SystemLogger.Log($"Reputation Block {requestedNodeId} not found in the Reputation DHT.");
                    return;
                }

                // Build the ReputationResponse packet
                var responseHeader = Packet.PacketBuilder.BuildPacketHeader(
                    Packet.PacketBuilder.PacketType.ReputationResponse,
                    node.Peer.NodeId,
                    node.Peer.Node_Type.ToString(),
                    node.Peer.PublicSignatureKey,
                    node.Peer.PublicEncryptKey,
                    node.Client.clientListenerPort,
                    node.Client.clientIP.ToString(),
                    5 // TTL value for response
                );

                var serializedBlock = JsonSerializer.Serialize(block);

                Packet responsePacket = Packet.PacketBuilder.BuildPacket(responseHeader, serializedBlock);
                byte[] serializedResponse = Packet.PacketBuilder.SerializePacket(responsePacket);

                // Encrypt with the requester's public key
                byte[] encryptedResponse = Encryption.EncryptPacketWithPublicKey(node, serializedResponse, packet.Header.PublicEncryptKey);

                // Send the response to the requester
                await node.NetworkManager.RetryAsync<bool>(async () =>
                {
                    bool success = await Client.SendPacketToPeerAsync(node, packet.Header.IPAddress, int.Parse(packet.Header.Port), encryptedResponse);
                    if (success)
                    {
                        SystemLogger.Log($"Successfully sent ReputationResponse for {requestedNodeId} to {packet.Header.IPAddress}:{packet.Header.Port}");
                    }
                    else
                    {
                        SystemLogger.Log($"Failed to send ReputationResponse for {requestedNodeId} to {packet.Header.IPAddress}:{packet.Header.Port}");
                    }

                    return success;
                });
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing ReputationRequest: {ex.Message}");
            }
        }

        //Process a Reputation Response.
        public static Task ProcessReputationResponse(Node node, Packet packet)
        {
            try
            {
                if (node == null)
                {
                    SystemLogger.Log("Error-ProcessReputationResponse: Node cannot be null.");
                }
                if (packet == null || packet.Header == null || packet.Content == null)
                {
                    SystemLogger.Log("Received an invalid ReputationResponse packet.");
                    return Task.CompletedTask;
                }

                // Deserialize the payload
                var block = JsonSerializer.Deserialize<Block>(packet.Content);

                if (block == null || string.IsNullOrWhiteSpace(block.Header.BlockId))
                {
                    SystemLogger.Log("Received an empty or invalid ReputationResponse payload.");
                    return Task.CompletedTask;
                }

                // Add the block to the Reputation DHT
                node.ReputationDHT.AddBlock(block);

                SystemLogger.Log($"Successfully added Reputation Block {block.Header.BlockId} to the Reputation DHT.");
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error processing ReputationResponse: {ex.Message}");
            }
            return Task.CompletedTask;
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
                    SystemLogger.Log($"Attempt {i + 1} failed: {ex.Message}");
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
                SystemLogger.Log($"Task error: {ex.Message}");
            }
        }

    }
}
