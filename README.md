# SPHERE Project

Welcome to the **SPHERE** (Secure Peer-to-Peer Hosted Encryption Record Exchange) repository!

SPHERE is a highly secure, decentralized framework designed for peer-to-peer communication, encrypted data exchange, and decentralized identity management. It offers robust privacy, data integrity, and cryptographic security while maintaining scalability and efficiency for various applications.

---

## Active Development

This project is a work in progress, with ongoing improvements to enhance security, scalability, and decentralized efficiency.

---

## Key Features

### Secure Contact List Management
- Unified, decentralized contact list across all SPHERE applications.
- Full user control over contacts, including key rotation and access permissions.
- Peer-to-peer (P2P) architecture eliminates reliance on centralized servers.

### End-to-End Encryption
- Uses **AES256**, **RSA2048**, and **ECDsa** algorithms for top-tier security.
- Dynamic key generation for each communication session.
- Private keys stored in secure local containers (CNG) without export unless explicitly allowed.

### Decentralized Networking
- Built on a **Distributed Hash Table (DHT)** for efficient peer discovery and data exchange.
- Uses a **Kademlia-based routing table** to optimize node connectivity.
- Integrated **Gossip Protocols** for propagating data across the network.

### Modular and Scalable Design
- Plug-and-play modules for encryption, authentication, routing, and token management.
- Scales efficiently even in resource-constrained environments (e.g., mobile clients).

### Digital Signature Verification
- Verifies message authenticity and integrity using **ECDsa** signatures.
- Prevents tampering and validates the origin of messages.

### Token-Based Proof of Work
- Implements a token system for peer validation and incentivized interactions.
- Tokens are issued for completed actions (e.g., message relays) and spent on data requests.

### Reputation Management
- Dynamic trust scores based on peer behavior and network contributions.
- Penalizes malicious actions and rewards reliable participation.

### High Scalability and Performance
- Adaptive sharding splits the DHT into manageable chunks.
- Dynamic load balancing ensures efficient resource use across nodes.

---

## Technical Breakdown

### Core Components

#### Encryption Module (`Encryption.cs`)
- Implements symmetric and asymmetric encryption.
- Hybrid key management for secure communications.
- Encrypted local symmetric keys (LSK) for contact data confidentiality.

#### Packet Management (`Packet.cs`)
- Defines and serializes packets for node-to-node communication.
- Includes validation for packet types, TTL, and cryptographic signatures.

#### Service Account Management (`ServiceAccountManager.cs`)
- Manages encryption keys bound to service accounts for added security.
- Uses CNG containers that prevent unauthorized key access.

#### Distributed Hash Table (DHT) (`DHT.cs`)
- Handles decentralized storage and retrieval of contact, reputation, and transaction blocks.
- Uses a **Kademlia-based routing algorithm** for efficient node lookups.

#### Networking Layer (`NetworkManager.cs`, `Client.cs`)
- Handles all network communication between nodes.
- Integrates **STUN/TURN** for NAT traversal and port discovery.

#### Reputation System (`Reputation.cs`)
- Evaluates node behavior based on network participation.
- Adjusts reputation scores dynamically.

---

## Security Features

- **End-to-End Encryption**: Each message is securely encrypted from sender to recipient.
- **Secure Key Exchange**: Uses Diffie-Hellman key exchange for secure session initiation.
- **Digital Signature Verification**: Validates message authenticity and integrity.
- **Anti-Replay Protection**: Prevents replay attacks using timestamped messages and nonces.

---

## Getting Started

### Prerequisites
- Visual Studio 2022 or later
- .NET Core SDK
- Basic understanding of distributed systems and C#

### Installation
```bash
git clone https://github.com/yourusername/SPHERE.git
```
1. Open `SPHERE.sln` in Visual Studio.
2. Build the solution to restore dependencies.
3. Run the project and bootstrap the network using available nodes.

---

## Contributing

We welcome contributions! Please fork the repository, create a feature branch, and submit a pull request. Issues and feature suggestions are also encouraged.

---

## License

This project is licensed under the [GPLv3 License](LICENSE).

---

## Acknowledgments
- Inspired by the need for secure and decentralized communication.
- Special thanks to contributors and the open-source community for ongoing support.

---

## Contact
For questions or support, contact [kl3mta3](https://github.com/kl3mta3) through GitHub or via email.
