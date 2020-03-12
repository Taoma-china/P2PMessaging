
import pyDes

import socket

import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from base64 import b64encode,b64decode
from Crypto import Random

def newkeys (keysize):
    random_generator = Random.new().read
    key=RSA.generate(keysize,random_generator)
    private,public = key,key.publickey()
    return public, private


(public_server, private_server) = newkeys(1024)
public_server=public_server.exportKey('PEM')
print (public_server)
private_server=private_server.exportKey('PEM')
message = 'qwert'
key = RSA.importKey(public_server)
cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(message)
print type(ciphertext)
key = RSA.importKey(private_server)
cipher = PKCS1_OAEP.new(key)
message = cipher.decrypt(ciphertext)
print message