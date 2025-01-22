
using SPHERE;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Blockchain
{
    public class DHT
    {

        private readonly Dictionary<string, Block> _blocks = new();

        public void AddBlock(Block block)
        {
            _blocks[block.Header.BlockId] = block;
        }

        public Block GetBlock(string blockID)
        {
            return _blocks.ContainsKey(blockID) ? _blocks[blockID] : null;
        }

        public void RemoveBlock(string blockID)
        {
            _blocks.Remove(blockID);

        }

        public void ReplaceBlock(string blockID, string encryptedContact, string signature)
        {
            Block block = GetBlock(blockID);
            if (block == null)
            {
                return;
            }
            if (SignatureGenerator.VerifyBlockSignature(blockID, signature, block.Header.PublicSignatureKey))
            {
                //add maybe reaching out to neighbors for overall confidence before fully Replacing the commit. 
                block.EncryptedContact = encryptedContact;
                block.Header.LastUpdateTime = DateTime.UtcNow;
            }
        }
    }
}
