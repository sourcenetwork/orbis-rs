## Participants 
* Alice -> Encryptor. Has file she wants to encrypt
* Bob -> Reder. Wants to read Alice's file
* Charlie -> Alice's Ring Node 1 
* Dave -> Alice's Ring Node 2
* Eve -> Developer. The person who sets up this instance of a ring and sets rules

### Pre Steps 
* Pre steps are requires before we have a more simpler flow of just Alice to Bob
* These steps are meant to set up the ring that alice can use 
* In a full system you should be able to choose 
    * Cryptography to use 
    * Threshold - Threshold of nodes needed for decryption 
    * Total Nodes (N) - total nodes to particpate in scheme

![diagram](sequenceDiagrams/PreSteps.svg)

### Encryption/Decryption Flow
* Now that presteps are done we can assume nodes are always running and exist in space
* There are still open questions of how to find said nodes in space and how to handle triggering and finding new nodes to join and exit but set that aside for now

![diagram](sequenceDiagrams/EncryptionDecryption.svg)

### Reshares/Refreshes
* Coming soon
* High level: 
* Refresh -> Nodes need to refresh their keys while maintaing the same secrets
    * Requires all nodes to come together to refresh
* Reshare -> Nodes need to invalidate an old node's keys and allow a new one to join
    * Requries T Nodes to come together to do a reshare
    * Everyone not in the reshare's keys will no longer work
    * New Nodes will now have an active share
* TODO: Requires A trigger to trigger this and select new nodes 
