#!/usr/bin/env python
import sys
import json
import os
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

def print_header(text):
        print ("")
        print ("---")
        print text
        print ("---")
        print ("")

def get_holder_id(): 
        holder_id =""
	print ("")
	print ("--")
        while not holder_id: 
                holder_id = raw_input("Holder identifier: ")
        return holder_id

def get_data_from_ledger(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName):
        valid_keys_list = [] 
	revokated_keys_list = []
	keys_list = []	
	unique_id = get_holder_id()

        api_read_ledger = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainName)
        print "Connection to the ledger"
        for data_loaded2 in api_read_ledger.liststreamkeyitems(streamName, unique_id):
                x = json.loads(data_loaded2["data"].decode("hex"))
		if not x:
                	print ("Holder does't exist")
                	print ("--")
                	print ("")
                	sys.exit()
		if (x["keyStatus"] == "publicKey"):
                	valid_keys_list.append([x["keyType"], x["keyfingerprint"]])
		if (x["keyStatus"] == "revokated"):
			revokated_keys_list.append([x["keyType"], x["keyfingerprint"]])
	for revokated_key in revokated_keys_list:
		if revokated_key in valid_keys_list:
			valid_keys_list.remove(revokated_key)
        return unique_id, valid_keys_list, revokated_keys_list

def write_DLT(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, unique_id, data, type_key):
	data = json.dumps(data)
        api_write_ledger = Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainName)
        api_write_ledger.publish(streamName, str(unique_id), data.encode("hex"))
        print ("")
        print ("--")
        print ("Wrote "+ type_key  +" into DLT: "+ chainName)
        print ("--")
        print ("")


def select_key_to_revoke(unique_id, valid_keys_list, revokated_keys_list):
	i = 0
	index_table =[]
	key_index_to_revoke =""
	print ("")
	print ("--")
	print ("Revocated keys:")
	for revokated_key in revokated_keys_list:
		print ("Type: "+ revokated_key[0] + " >> Key fingerprint: "+ revokated_key[1])
	print ("")
	print ("-")
	print ("Choose key to revoke:")
	for valid_key in valid_keys_list: 
		i +=1
		print (str(i) +" = Type: "+ valid_key[0] + " >> Fingerprint: "+ valid_key[1])
		index_table.append(i)
	#while key_index_to_revoke not in index_table: (not work for the moment)
	key_index_to_revoke = int(raw_input("Select key number to revoke: "))
	key_index_to_revoke -=1
	#print "key to revoke: "+ str(valid_keys_list[key_index_to_revoke])
	return valid_keys_list[key_index_to_revoke]

#test key 651635109304031167401617626627
def generate_data_for_ledger(holder_identifier, key_type, key_fingerprint):
        public_data = { 
                'version' : 0.0,
                'holderID' : holder_identifier,
                'keyType' : key_type,
                'keyStatus' : "revokated",
                'keyfingerprint' : key_fingerprint 
                }
        public_data_json = json.dumps(public_data)
        return public_data_json

def revoke_key(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName):
	unique_id, valid_keys_list, revokated_keys_list = get_data_from_ledger(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName)
	key_to_revoke = select_key_to_revoke(unique_id, valid_keys_list, revokated_keys_list)
	data_to_write =  json.loads(generate_data_for_ledger(unique_id, key_to_revoke[0], key_to_revoke[1]))
	write_DLT(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName, unique_id, data_to_write, data_to_write["keyType"])	
if __name__ == '__main__':
	test_dlt()
	rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName = get_dlt_credentials()
	revoke_key(rpcuser, rpcpasswd, rpchost, rpcport, chainName, streamName)
