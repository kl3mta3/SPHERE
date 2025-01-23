
using SPHERE;
using SPHERE.Configure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Blockchain
{
    /// <summary>
    /// The Distributed Hash Table.
    /// 
    /// The DHT is the Blockchain it is the nodes record of the chain, either all or its shard(Piece).
    /// 
    /// it is a Dictonary of Blocks with a key of their ID.
    /// 
    /// Blocks can be added to the DHT and edited, That is all. 
    /// 
    /// It exists exactly the same in all forms across all devices whether they have a shard or the whole Chain.
    /// </summary>
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
