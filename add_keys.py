#!/usr/bin/env python
import random
import hashlib
import json
import os
import sys
from Savoir import Savoir
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512

random_length = 30
key_length = 3072

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

# Generate unique id number from random, card number length as parameter 
# Source https://stackoverflow.com/questions/2673385/how-to-generate-random-number-with-the-specific-length-in-python
# To do: check if the card number exist within the blockchain
	#to do verify if the id exit into the ledger

def print_header(text):
        print ("")
        print ("---")
        print text
        print ("---")
        print ("")

def get_PIN():
        PIN1 = 0
        PIN2 = 1
        print_header("PIN code for protecting data into secure badge:")
        while PIN1 != PIN2:
                PIN1 = raw_input("Choose a PIN code: ")
                while not PIN1:
                        PIN1 = raw_input("Choose a PIN code: ")
                PIN2 = raw_input("Confirm PIN code: ")
                while not PIN2:
                        PIN2 = raw_input("Confirm PIN code: ")
                if PIN1 != PIN2:
                        print ("Error! PIN codes are different")
        return PIN1

def generate_key(key_length):
        random = Random.new().read
        private_key = RSA.generate(key_length, random)
        return private_key

def generate_hash(data):
        data_hash = SHA512.new(data)
        return data_hash

def protect_private_key(private_key, PIN):
        protected_private_key = private_key.exportKey(format = 'PEM', passphrase = PIN, pkcs=1)
        return protected_private_key

def generate_data_ledger(holder_id, key_length, key_type):
	private_key = generate_key(key_length)
	public_data = {
		'version' : 0.0,
		'holderID' : holder_id,
		'keyType' : key_type,
		'keyStatus' : "publicKey",
		'publicKey' : (private_key.publickey()).exportKey('PEM'),
		'keyfingerprint' : (generate_hash((private_key.publickey()).exportKey('PEM'))).hexdigest()
		}
	public_data_json = json.dumps(public_data)
	return public_data_json, private_key

def write_DLT(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, unique_id, data, type_key):
        api_write_ledger = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainName)
        api_write_ledger.publish(streamName, str(unique_id), data.encode("hex"))
        print ("")
        print ("--")
        print ("Wrote "+ type_key  +" into DLT: "+ chainName)
        print ("--")
        print ("")

def generate_local_data(holder_id, key_length, PIN, key_type):
	data_ledger, private_key  =  generate_data_ledger(holder_id, key_length, key_type)	

	key_field = "'Private"+ key_type+"'"

	json_private_key ={
                'version' : 0.0,
                'holderID' : holder_id,
                key_field : private_key.exportKey(format = 'PEM', pkcs=1)
                }

	json_protected_private_key ={
		'version' : 0.0,
		'holderID' : holder_id,
		key_field : private_key.exportKey(format = 'PEM', passphrase = PIN, pkcs=1)
		}

	if not (os.path.isdir("output")):
		os.makedirs("output")

	path = "output/" + str(holder_id)
	
	if not (os.path.isdir(path)):
		os.makedirs(path)

	unprotected_keys_file = path + "/private_"+key_type+".json"

	with open(unprotected_keys_file, 'w') as f:
		json.dump(json_private_key, f)
	
	protected_keys_file = path + "/private_"+key_type+".secure"

	with open(protected_keys_file, 'w') as f:
	 	json.dump(json_protected_private_key, f)

        return data_ledger, key_type

def check_entry_ledger(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, unique_id):
	keys_list =[]
	api_read_ledger = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainName)
	print "Connection to the ledger"
	for data_loaded2 in api_read_ledger.liststreamkeyitems(streamName, unique_id):
		x = json.loads(data_loaded2["data"].decode("hex"))
		keys_list.append([x["keyType"], x["keyfingerprint"]])
	return keys_list 

def print_keys(keys):
	print ("")
	print ("---")
	if not keys:
		print ("Holder does't exist")
		print ("--")
		print ("")
		sys.exit()
	print "Existing keys for this holder :"
	#print (len(keys))
	for key in keys:
		print "Type: "+ key[0] + " >> Fingerprint: "+ key[1]
	return (keys)

def choose_key_to_generate(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, key_length, holder_id):
	key_type = ''
	print ""
	print "--"
	print "--"
	print ("Which type of key to generate:")
	print ("1 = encryption key")
	print ("2 = signature key")
        while not key_type or key_type not in ["1","2"]:
		key_type = raw_input("Choose 1 or 2: ")
	if key_type == "1":
		print ("new encryption key")
		PIN = get_PIN()
		encryption_data, type_encryptionKey = generate_local_data(holder_id, key_length, PIN, "EncryptionKey")
		write_DLT(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, holder_id, encryption_data, type_encryptionKey)
	elif key_type == "2":
		print ("new signature key")
		PIN = get_PIN()
		print ("")
		signature_data, type_signatureKey =  generate_local_data(holder_id, key_length, PIN, "signatureKey")
		write_DLT(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, holder_id, signature_data, type_signatureKey)
	
def global_function(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, key_length):
	ledger_key = ""
	print_header("Key generator for the ledger")
	
	while not ledger_key:
		ledger_key = raw_input("Holder number: ")	
	keys_list = check_entry_ledger(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, ledger_key)
	print_keys(keys_list)
	choose_key_to_generate(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, key_length, ledger_key)
	
if __name__ == '__main__':
	test_dlt()
	rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName = get_dlt_credentials()
	global_function(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, key_length)
