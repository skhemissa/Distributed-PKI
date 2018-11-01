# Distributed Public Key Infrastructure
	
## Description
Two kind of entries in the ledger : entries that contains public keys and entries that contains revokated keys. 
	
A holder has an unique ID. This ID is used has identifier of an entry into the ledger.

The entry contains also a json object that contain the following values :
	type = two possible values: signatureKey or encryptionKey
	status = two possible values: publicKey, revokated
	KeyFingerprint = the fingerprint of the public key (SHA512 hash) 
		https://docs.python.org/2/library/hashlib.html
	publicKey = the public key in PEM format
		This field isn't included into a revocation entry intoo the ledger

To secure their communication, both parties can share their ID and public key fingerprint.

Only some nodes can write and revoked keys into the ledger (Permissionned Ledger).
By default, other node can read the ledger.


## Usage

## Initialization
Global set up:
- Install Multichain... very easy : https://www.multichain.com/download-install/

- Create the Ledger 
```
	multichain-util create distributedPKI
```
- Allow all nodes to read the ledger
	change the chain parameter into the following file $HOME/.multichain/distributedPKI/params.dat 
		anyone-can-connect = true

- Restart the ledger to apply new configuration 
	Run the following command: 
		multichaind distributedPKI -daemon
	The communication port number between nodes is displayed, otherwise it is available in $HOME/.multichain/distributedPKI/params.dat, value of default-rpc-port

- create a stream, the container of keys: 
	Run the following command:
		multichain-cli distributedPKI
	Whitin the Multichain CLI, run the following commands :
		> create stream publicKeys false
		> exit
- Install pip (Package manager for Python): sudo apt-get install python-pip
- Install Savoir, a JsonRPC wrapper for Multichain:
        pip install savoir
        if you get the following error message when you run a script : "ImportError: No module named Savoir" see https://github.com/DXMarkets/Savoir/issues/6#issuecomment-335036784

- Into the D-PKI scripts directory, update the file ledger.conf with the following inputs :
        rpcport >> from file $HOME/.multichain/distributedPKI/params.dat get the value for default-rpc-port    
        rpcuser and rpcpassword >> from file $HOME/.multichain/distributedPKI/multichain.conf
        no change for rpchost, chainName, streamName



GREAT : you can use the script library on this node.


- Adding a new node to the distributed ledger :
	Install Multichain
		run the following command :
			multichaind distributedPKI@[ip-address]:[port]
		The ip-address and port are related to the first node
		The wallet_id of this node is displayed
	
	On the first node, run the following commands:
		multichain-cli distributedPKI grant wallet_id connect, receive
		multichain-cli grant wallet_id stream1.write
	
	On the second node:
	multichaind distributedPKI -daemon
	... wait few minutes for synchronization

	Install Savoir.

	Update the ledger.conf file with the local data:

