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


# Setup
Please read setup.txt file to initialize the environment
