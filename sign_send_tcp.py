#!/usr/bin/env python
import os
import sys
import json
import base64
import socket
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_PSS

HOST = '192.168.0.100'
PORT = 50000

mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def grap_terminal(text_2_display):
	text=""
	while not text:
		text = raw_input(text_2_display + ": ")
	return text

def get_contain_2_sign():
	contain_2_sign = grap_terminal("Message to sign")
	return contain_2_sign

def get_holder_id():
	holder_id = grap_terminal("Holder id")
	return holder_id	


def get_private_signature_key():
	private_key = ""
	holder_id = get_holder_id()
	key_file = "output/"+ holder_id +"/private_signatureKey.secure"
	with open(key_file) as file:
		data = json.load(file)
	protected_private_key = data["PrivatesignatureKey"]
	PIN = get_PIN()
	private_key = unprotect_private_key(protected_private_key, PIN)
	return holder_id, private_key

def get_PIN():
	PIN = ""
	while not PIN:
		PIN = raw_input("Enter your PIN: ")
	return PIN

def unprotect_private_key(protected_private_key, PIN):
	unprotected_private_key = RSA.importKey(protected_private_key, passphrase = PIN)
	return unprotected_private_key

def generate_hash(data):
	data_hash = SHA512.new(str(data))
	return data_hash

def encode_data(data):
	encoded_data = base64.b64encode(data)
	return encoded_data

def sign_data():
	data_2_sign = get_contain_2_sign()
	data_hash = generate_hash(data_2_sign)
	holder_id, private_key = get_private_signature_key()
	signer = PKCS1_PSS.new(private_key)
	digitale_signature = signer.sign(data_hash)
	return holder_id, digitale_signature, data_2_sign

def generate_signature_file():
	holder_id, digitale_signature, data_2_sign = sign_data()
	signature_data = {
		'Version' : 0.0,
		'HolderID' : holder_id,
		'DigitaleSignature' : encode_data(digitale_signature),
		'SignedData' : data_2_sign
		}
	signature_json = json.dumps(signature_data)
	#print signature_json
	return signature_json

def send_by_socket(data_2_send):
	try:
		mySocket.connect((HOST, PORT))
	except socket.error:
    		print "Connection failed."
    		sys.exit()    
	print "Connection to the server."    

	print ("")
	print ("Data transmitted:")
	print data_2_send
    	mySocket.send(data_2_send)

	print "Connection closed."
	mySocket.close()

if __name__ == '__main__':
	os.system("clear")
	print( "test holder 627165394295836034418436878389")
	
	data_2_send = generate_signature_file()
	send_by_socket(data_2_send)
