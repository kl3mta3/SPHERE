using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Client
{
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
