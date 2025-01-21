using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Client
{
    public class PacketBuilder
    {
        MemoryStream _ms;

        public PacketBuilder()
        {
            _ms = new MemoryStream();
        }

        public void WriteOpCode(byte opcode)
        {

            _ms.WriteByte(opcode);

        }

        public void WriteMessage(string message)
        {
            var messageLength = message.Length;

            _ms.Write(BitConverter.GetBytes(messageLength), 0, 4);
            _ms.Write(Encoding.ASCII.GetBytes(message), 0, messageLength);

        }

        public Byte[] GetPacketBytes()
        {

            return _ms.ToArray();
        }

    }
}
