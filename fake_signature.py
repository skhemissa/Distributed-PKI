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
holder_id = "627165394295836034418436878389"
digitale_signature = "nYO8GiEb8N6yvFqARK/D8xz3X6n8HYSkgMzN1/Vv6W01fQEQCCGpdu02ttfpT7cgrFC52XOl9g0qihP6uksTgjBKaq/1Bak7fB+5yPeU5JbX8guMJdYrszDDbx7qrr8PsLt+jNmsXIhgBQyKLuv9/6zKLDSU+IPWbSKL/3lFlEw47j5tMW3X4ichzwBg4CaE4ph0GQMaRe2RoQMIYKoH9WUd3EJycGzTt4mV15FDiJOAUvh5FVNhu8GYAFdSmN8cw3xFHrfULf+tZDzy4pHd3qPXyJWKKScjp/S3M4V71BTj+LOQ+J4vXJ1Ul45uod0pgrJj6gFa7GV5xX9yRCP0215oNGFDJl5YCTtagqYKJsDHk3XIe49v6wvx8/nYDnVpGZKx5GK0FMpFo7qrKcyMNLsXx/2Hdmmm7TnGb4Q5BpuUZTZb3yxgXLaNdjD38Q1fmdzfh2HRs43/HzFHYfiEGfdhtDB9MCjhG0c6CG/JAxGTFxacgpZJ3Ob5N2YbWCvi"
data_2_sign = "test"

def encode_data(data):
	encoded_data = base64.b64encode(data)
	return encoded_data

def generate_signature_file(holder_id, digitale_signature, data_2_sign):
	signature_data = {
		'Version' : 0.0,
		'HolderID' : holder_id,
		'DigitaleSignature' : digitale_signature,
		'SignedData' : data_2_sign
		}
	signature_json = json.dumps(signature_data)
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
	
	data_2_send = generate_signature_file(holder_id, digitale_signature, data_2_sign)
	send_by_socket(data_2_send)
