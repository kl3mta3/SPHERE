using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Client
{
    /// <summary>
    /// The PacketReader is used to read incoming Packets. 
    /// 
    /// At the moment it is jsut reading a message this is missing its fucntionality as it is next to finish. 
    /// 
    /// The packet reader will convert the steam back into a serilized pack once that happens it can use the packet type to process the packet accourdingly.
    /// 
    /// </summary>
    public  class PacketReader: BinaryReader
    {
            private NetworkStream _stream;
            public PacketReader(NetworkStream stream) : base(stream)
            {

                _stream = stream;

            }

            public async Task<string>  ReadMessage()
            {
                Byte[] buffer;
                var length = ReadInt32();
                buffer = new Byte[length];
                _stream.Read(buffer, 0, length);

                var message = Encoding.ASCII.GetString(buffer);

                return message;
            }
    }
}
