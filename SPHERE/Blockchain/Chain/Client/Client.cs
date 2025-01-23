using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Client
{

    /// <summary>
    /// The client is a standard TCP/IP listener. 
    /// We use STUN (Session Traversal Utilities for NAT) to get a port and Ip for the listener to allow the client to connect and listen to the outside world without portfowarding.
    /// 
    /// Sent Packets are sent dynamically so no other work is needed,
    /// 
    /// The client will get packets from the Node and send them to the requested address
    /// Or the client listener will get Packets from other Nodes and send them to the Packet reader to be processed. 
    /// 
    /// 
    /// </summary>
    public class Client
    {
        private const int StartPort = 5000;                     // Start of the port range
        private const int EndPort = 6000;                       // End of the port range
        public TcpClient client;
        public TcpListener Listener;
        public PacketBuilder packetBuilder;
        public PacketReader packetReader;

        public string clientIP ;
        public int clientListenerPort=0;                             //Port for listening to incoming messages Should be static and provided to other clinets 
        public int clientCommunicationPort;


        public static async Task SendMessageToPeerAsync(string ip, int port, string message)
        {
            try
            {
                using TcpClient client = new TcpClient();
                await client.ConnectAsync(ip, port);

                using NetworkStream stream = client.GetStream();

                // Send a message
                byte[] data = Encoding.UTF8.GetBytes(message);
                await stream.WriteAsync(data, 0, data.Length);

   
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        public static void SetRandomListenerPort(Client client)
        {

            int port = FindAvailablePort();

            client.clientListenerPort = port;


        }

        public static int FindAvailablePort()
        {
            for (int port = StartPort; port <= EndPort; port++)
            {
                if ( IsPortAvailableAsync(port))
                {
                    return port;
                }


            }
            throw new Exception("No available ports found in the specified range.");
        }

        private static bool IsPortAvailableAsync(int port)
        {
            
                try
                {
                    using (var listener = new TcpListener(IPAddress.Any, port))
                    {
                        listener.Start();
                        listener.Stop();
                        return true;
                    }
                }
                catch (SocketException)
                {
                    return false;
                }
           
        }

        public static async Task StartClientListenerAsync(Client client)
        {
            
            if(client.clientListenerPort==0)
            {
                client.clientListenerPort = FindAvailablePort();

            }
            
            client.Listener = new TcpListener(IPAddress.Any, client.clientListenerPort);
            client.Listener.Start();
            Console.WriteLine($"Async server is listening on port {client.clientListenerPort}");

            while (true)
            {
                try
                {
                    client.client = await client.Listener.AcceptTcpClientAsync();
                    Console.WriteLine($"Connection established with {client.client.Client.RemoteEndPoint}");

                    _ = HandleClientAsync(client.client); 
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Server error: {ex.Message}");
                }
            }
        }

        private static async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                using NetworkStream stream = client.GetStream();
                using PacketReader reader = new PacketReader(stream);

                while (client.Connected)
                {
                    // Read the incoming message using the PacketReader
                    string message = await reader.ReadMessage();
                    Console.WriteLine($"Received message: {message}");


                    // message needs to be sent to node processed encrypted. 

                    //(Missing Fucntionality) will add. 
                  
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Client handling error: {ex.Message}");
            }
            finally
            {
                client.Close();
            }
        }
    }


}

