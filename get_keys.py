#!/usr/bin/env python
import json
import sys
from Savoir import Savoir

def get_dlt_credentials():
	f = open('ledger.conf')
	#line = f.read().splitlines()
	for line in f:
		line = line.strip()
		var = line.split(" ")
		if (var[0] == "rpcuser"):
			rpcuser = var[1]
		if (var[0] == "rpcpasswd"):
			rpcpasswd = var[1]
		if (var[0] == "rpchost"):
			rpchost = var[1]
		if (var[0] == "rpcport"):
			rpcport = var[1]
		if (var[0] == "chainName"):
			chainName = var[1]
		if (var[0] == "streamName"):
			streamName = var[1]

	if (not rpcuser) or (not rpcpasswd) or (not rpchost) or (not rpcport) or (not chainName) or (not  streamName):
		print ("Missed ledger configuration")
		sys.exit()		
	f.close()
	return rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName

def test_dlt():
	rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName = get_dlt_credentials()
	api = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainName)
	try:
		api.getinfo()
		print ("")
		print ("Ledger client running!")
		print ("")
		print ("-")
		print ("")
	except:
		print ("")
		print ("Ledger client not started!")
		print ("")
		print ("Please run the following command : multichaind "+ chainName +" -daemon")
		print ("")
		sys.exit()

def get_holder_id(): 
        holder_id ="" 
        print ("")
        print ("--")
        while not holder_id: 
                holder_id = raw_input("Holder identifier: ")
        return holder_id

def print_keys(key_list, key_status, key_type):
	print ("____________________________________")
	print (key_status + " " + key_type +" keys:")
	print ("---------------------------------------------")
	for key in key_list:
		print ("Key fingerprint: "+key[0])
		print ("")
	if (len(key_list) > 1) and (key_status == "Valid"):
		print ("/!\ >> Warning! More then one valid " + key_type +" key.")
		print ("/!\ /!\ >> Please revoke additional keys.")

def get_keys_from_ledger():
        valid_encryption_keys = []  
        revokated_encryption_keys = []
	valid_signature_keys = []
	revokated_signature_keys = []

        keys_list = []  
        holder_id = get_holder_id()

	rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName = get_dlt_credentials()

        api_read_ledger = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainName)
        print "Connection to the ledger"
        for data_loaded2 in api_read_ledger.liststreamkeyitems(streamName, holder_id):
                x = json.loads(data_loaded2["data"].decode("hex"))
                if not x:
                        print ("Holder does't exist")
                        print ("--")
                        print ("")
                        sys.exit()
                if (x["keyStatus"] == "publicKey") and (x["keyType"] == "EncryptionKey"):
                        valid_encryption_keys.append([x["keyfingerprint"]])
                if (x["keyStatus"] == "revokated") and (x["keyType"] == "EncryptionKey"):
                        revokated_encryption_keys.append([x["keyfingerprint"]])
		if (x["keyStatus"] == "publicKey") and (x["keyType"] == "signatureKey"):
                        valid_signature_keys.append([x["keyfingerprint"]])
                if (x["keyStatus"] == "revokated") and (x["keyType"] == "signatureKey"):
                        revokated_signature_keys.append([x["keyfingerprint"]])
	for revokated_encypted_key in revokated_encryption_keys:
		if revokated_encypted_key in valid_encryption_keys:
			valid_encryption_keys.remove(revokated_encypted_key)
	for revokated_signature_key in revokated_signature_keys:
		if revokated_signature_key in valid_signature_keys:
			valid_signature_keys.remove(revokated_signature_key)
	print ("-")
	print_keys(valid_encryption_keys, "Valid", "encryption")
	print_keys(revokated_encryption_keys, "Revokated", "encryption")
	print_keys(valid_signature_keys, "Valid", "signature")
	print_keys(revokated_signature_keys, "Revokated", "signature")
        return holder_id, valid_encryption_keys, revokated_encryption_keys, valid_signature_keys, revokated_signature_keys

if __name__ == '__main__':
	test_dlt()
	get_keys_from_ledger()
