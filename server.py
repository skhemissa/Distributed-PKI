#!/usr/bin/env python
# https://python.developpez.com/cours/TutoSwinnen/?page=page_20

import socket, sys
import os
import json
import base64
from Savoir import Savoir
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
HOST = '192.168.0.100'
PORT = 50000

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

def get_keys_from_ledger(holder_id):
	rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName = get_dlt_credentials()
        valid_encryption_keys = []
        revokated_encryption_keys = []
        valid_signature_keys = []
        revokated_signature_keys = []

        keys_list = []

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
                        valid_encryption_keys.append([x["publicKey"]])
                if (x["keyStatus"] == "revokated") and (x["keyType"] == "EncryptionKey"):
                        revokated_encryption_keys.append([x["publicKey"]])
                if (x["keyStatus"] == "publicKey") and (x["keyType"] == "signatureKey"):
                        valid_signature_keys.append([x["publicKey"]])
                if (x["keyStatus"] == "revokated") and (x["keyType"] == "signatureKey"):
                        revokated_signature_keys.append([x["publicKey"]])
        for revokated_encypted_key in revokated_encryption_keys:
                if revokated_encypted_key in valid_encryption_keys:
                        valid_encryption_keys.remove(revokated_encypted_key)
        for revokated_signature_key in revokated_signature_keys:
                if revokated_signature_key in valid_signature_keys:
                        valid_signature_keys.remove(revokated_signature_key)
        print ("-")
        return valid_encryption_keys, valid_signature_keys

def generate_hash(data):
        data_hash = SHA512.new(data)
        return data_hash

def verify_digitale_signature(data, digitale_signature, public_key):
        signature_public_key = RSA.importKey(public_key)
        data_hash = generate_hash(data)
        verifier = PKCS1_PSS.new(signature_public_key)
	print ("-")
	print ("")
	print ("PKCS1 PSS signature verification:")
        if verifier.verify(data_hash,base64.b64decode(digitale_signature)):
                print ("-")
                print ("--")
                print ("> Valid signature")
                print ("--")
                print ("-")
        else:   
                print ("-")
                print ("--")
                print ("> /!\ /!\ WARNING ! INVALID SIGNATURE /!\ /!\/")
                print ("--")
                print ("-")

def start_server(HOST, PORT):
	mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
    		mySocket.bind((HOST, PORT))
	except socket.error:
    		print "TCP initialization faillure...."
    		sys.exit()

	while 1:
    		os.system("clear")
    		print ("")
    		print ("_______________________________________________________")
    		print "Node ready, waiting for connection..."
    		print ("_______________________________________________________")
		
    		mySocket.listen(5)
    
    		connection, address = mySocket.accept()
    		print " "
    		print "--"
    		print "Client connected, address IP %s, port %s" % (address[0], address[1])
    
   		while 1:
			msgClient = connection.recv(1024)
    			if msgClient =="":
            			break
			print (" ")
			print ("Received data:")
			print ("")
			data_json = json.loads(msgClient)
			holder_id = data_json["HolderID"]
			message_signature = data_json["DigitaleSignature"]
			message = data_json["SignedData"]
			print ("Message:")
			print message
			print ("")
			print ("Holder id:")
			print holder_id
			print ("")
			print ("Digitale signature of the message:")
			print message_signature
			print ("")
			print ("Raw data:")
			print msgClient
			print "-"	
			valid_encryption_keys, valid_signature_keys = get_keys_from_ledger(holder_id)
			if (len(valid_signature_keys) > 1):
				print ("Too many valid signature keys !!!!")
				sys.exit()
			for key in valid_signature_keys:
				public_key =  key[0]
			print ("Get signature public key for:")
			print public_key
			print ("")
			verify_digitale_signature(message, message_signature, public_key)
			raw_input("Press entrer> ")
    	print "Connexion ended."
    	connection.close()

if __name__ == '__main__':
	test_dlt()
	start_server(HOST, PORT)
