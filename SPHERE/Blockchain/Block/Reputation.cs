using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using SPHERE.Configure;
using SPHERE.Configure.Logging;

namespace SPHERE.Blockchain
{
    public class Reputation
    {
        public enum ReputationReason
        {
            GetContactSuccessful,
            GetContactFailed,
            PutContactSuccessful,
            PutContactFailed,
            GetTransactionSuccessful,
            GetTransactionFailed,
            PutTransactionSuccessful,
            PutTransactionFailed,
            BootStrapSuccessful,
            BootStrapFailed,
            PingSuccessful,
            PingFailed,
        }

        public static readonly Dictionary<ReputationReason, double> ReputationReasons = new Dictionary<ReputationReason, double>
        {

            { ReputationReason.GetContactSuccessful, .3 },
            { ReputationReason.GetContactFailed, -.25 },
            { ReputationReason.PutContactSuccessful, .3 },
            { ReputationReason.PutContactFailed, -.25 },
            { ReputationReason.GetTransactionSuccessful, .3 },
            { ReputationReason.GetTransactionFailed, -.25 },
            { ReputationReason.PutTransactionSuccessful, .3 },
            { ReputationReason.PutTransactionFailed, -.25 },
            { ReputationReason.BootStrapSuccessful, 2 },
            { ReputationReason.BootStrapFailed, -1.5 },
            { ReputationReason.PingSuccessful, .1 },
            { ReputationReason.PingFailed, -.25 }

        };

        [JsonPropertyName("NodeId")]
        public string NodeId { get; set; }
        [JsonPropertyName("ReputationScore")]
        public double ReputationScore { get; set; } = new();
        [JsonPropertyName("ReputationChange")]
        public double ReputationChange { get; set; } = new();
        [JsonPropertyName("UpdateNumber")]
        public int UpdateNumber { get; set; } = new();
        [JsonPropertyName("TotalUpdates")]
        public int TotalUpdates { get; set; } = new();
        [JsonPropertyName("LastUpdated")]
        public DateTime LastUpdated { get; set; } = new();
        [JsonPropertyName("Reason")]
        public string Reason { get; set; }
        [JsonPropertyName("Signature")]
        public string Signature { get; set; }
        [JsonPropertyName("UpdateIssuedByNodeId")]
        public string UpdateIssuedByNodeId { get; set; }

        public static double ParseReputationReason(ReputationReason reason)
        {
            return ReputationReasons[reason];
        }

        public static Reputation.ReputationReason GetReputationReasonFromString(string input)
        {
            if (Enum.TryParse<Reputation.ReputationReason>(input, true, out var reason))
            {
                return reason;
            }
            else
            {
                throw new ArgumentException($"Invalid reputation reason: {input}", nameof(input));
            }
        }

        public Reputation CreateReputation(string receivingNodeId, string issuingNodeId, Reputation.ReputationReason reason)
        {


            Reputation reputation = new Reputation
            {
                NodeId = receivingNodeId,
                ReputationScore = Reputation.ParseReputationReason(reason),
                ReputationChange = Reputation.ParseReputationReason(reason),
                UpdateNumber = 1,
                TotalUpdates = 1,
                LastUpdated = DateTime.UtcNow,
                Reason = reason.ToString(),
                Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes(NodeId + ReputationScore + ReputationChange + UpdateNumber + TotalUpdates + LastUpdated + Reason + UpdateIssuedByNodeId))),
                UpdateIssuedByNodeId = issuingNodeId
            };
            return reputation;
        }

        public static Reputation UpdatedReputation(Reputation reputation, string issuingNodeId, Reputation.ReputationReason reason)
        {


            reputation.LastUpdated = DateTime.UtcNow;
            reputation.ReputationChange = Reputation.ParseReputationReason(reason);
            reputation.ReputationScore += Reputation.ParseReputationReason(reason);
            reputation.UpdateNumber += 1;
            reputation.TotalUpdates += 1;
            reputation.Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes(reputation.NodeId + reputation.ReputationScore + reputation.ReputationChange + reputation.UpdateNumber + reputation.TotalUpdates + reputation.LastUpdated + reputation.Reason + reputation.UpdateIssuedByNodeId)));
            reputation.UpdateIssuedByNodeId = reputation.NodeId;
            return reputation;



        }

       
    }

    
}
