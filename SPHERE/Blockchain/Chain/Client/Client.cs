using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Client
{
    public class Client
    {
        public TcpClient client;
        public PacketBuilder packetBuilder;
        public PacketReader packetReader;

        public string clientIP ;
        public int clientPort;


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


        public static async Task StartServerAsync(int port)
        {
            TcpListener server = new TcpListener(IPAddress.Any, port);
            server.Start();
            Console.WriteLine($"Async server is listening on port {port}");

            while (true)
            {
                try
                {
                    TcpClient client = await server.AcceptTcpClientAsync();
                    Console.WriteLine($"Connection established with {client.Client.RemoteEndPoint}");

                    _ = HandleClientAsync(client); // Fire-and-forget the client handler
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
                    string message = reader.ReadMessage();
                    Console.WriteLine($"Received message: {message}");

                    // You can handle the message further here, e.g., log, forward, or process it.
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

