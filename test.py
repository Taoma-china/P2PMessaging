# -*- coding: utf-8 -*-
import pyDes

import socket

import threading

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from base64 import b64encode,b64decode
from Crypto import Random
hash = "SHA-256"

Des_Key = b'qwerasdf'

Des_IV = b"\x00\x00\x00\x00\x00\x00\x00\x00"

PORT = 4396

BUFF = 1024


def newkeys (keysize):
    random_generator = Random.new().read
    key=RSA.generate(keysize,random_generator)
    private,public = key,key.publickey()
    return public, private
def DesEncrypt(str):

    k = pyDes.des(Des_Key, pyDes.CBC, Des_IV, pad = None, padmode = pyDes.PAD_PKCS5)

    Encrypt_Str = k.encrypt(str)

    return Encrypt_Str

def DesDecrypt(str):

    k = pyDes.des(Des_Key, pyDes.CBC, Des_IV, pad = None, padmode = pyDes.PAD_PKCS5)

    Decrypt_Str = k.decrypt(str)

    return Decrypt_Str

def SendMessage(Sock, test):

    while True:

        SendData = input()
        

        encryptdata = DesEncrypt(SendData)

        print('encrypted data is ' + str(encryptdata))

        if len(SendData) > 0:

            Sock.send(encryptdata)

def RecvMessage(Sock, test):

    while True:

        Message = Sock.recv(BUFF)

        decryptdata = DesDecrypt(Message)

        if len(Message)>0:

            print("receive message:" + decryptdata.decode('utf8'))
            
            
def importKey(externKey):
    return RSA.importKey(externKey)

def encrypt(message, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)

def main():

    user = input('please input server or client:')

    if user == 'server':

        ServerSock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

        ServerSock.bind(('127.0.0.1',PORT))

        ServerSock.listen(5)

        print("listening......")
        
        (public_server, private_server) = newkeys(1024)
        ConSock,addr = ServerSock.accept()
        ConSock.sendall(public_server.exportKey('PEM'))
        #print public_server.exportKey('PEM')
        pub_cli_key = ConSock.recv(BUFF)
        #thread_s = threading.Thread(target = SendMessage, args = public_server.exportKey('PEM'))
        
        RSA_pub_cli = RSA.importKey(pub_cli_key)
        ser_passw_input = input('input the password').encode()
        #print encrypt(ser_passw_input,RSA_pub_cli)
        ConSock.sendall(encrypt(ser_passw_input,RSA_pub_cli))
        
        RSA_pri_ser = RSA.importKey(private_server.exportKey('PEM'))
        
        
        passw_receiv_cli = ConSock.recv(BUFF)
        dec_cli_passw = PKCS1_OAEP.new(RSA_pri_ser).decrypt(passw_receiv_cli)
        #print (dec_cli_passw)
        #print ser_passw_input
        if ser_passw_input != dec_cli_passw:
            ConSock.send("invalid password")
            #print ConSock.recv(BUFF)
            #print ConSock.recv(BUFF)
            ConSock.close()
            return
        else:
            print ('ssss')
            #ConSock.recv(BUFF)                       
            #ConSock.send("correct password")

                    
        
        

            
        print('connection succeed' + '\n' + 'you can chat online')
        
        thread_1 = threading.Thread(target = SendMessage, args = (ConSock, None))

        thread_2 = threading.Thread(target = RecvMessage, args = (ConSock, None))

        thread_1.start()

        thread_2.start()

    elif user == 'client':

        ClientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        ServerAddr = input("please input the server's ip address:")
        
        ClientSock.connect((ServerAddr, PORT))
        (public_client, private_client) = newkeys(1024)
        
        ClientSock.sendall(public_client.exportKey('PEM'))
        pub_ser_key=ClientSock.recv(BUFF)
        #print pub_ser_key
        
        RSA_pub_ser = importKey(pub_ser_key)
        #print RSA_pub_ser.exportKey('PEM')
        
        cli_passw_input = input('input the password').encode()
        ClientSock.sendall(encrypt(cli_passw_input,RSA_pub_ser))
        passw_receiv_ser = ClientSock.recv(BUFF)
        #print passw_receiv_ser
        #print('---------')
        
        RSA_pri_cli = RSA.importKey(private_client.exportKey('PEM'))
        
        
        dec_ser_passw = PKCS1_OAEP.new(RSA_pri_cli).decrypt(passw_receiv_ser)
        #print dec_ser_passw
        if cli_passw_input != dec_ser_passw:
            ClientSock.send("invalid password")
            #print ClientSock.recv(BUFF)
            #print ClientSock.recv(BUFF)
            ClientSock.close()
            return
        else:

            print ('cccc')

           # ClientSock.send("correct password")
          #  ClientSock.recv(BUFF)  
            #print ClientSock.recv(BUFF)           
        
        
        

        print('connection succeed, chat start!')
        
            
        thread_3 = threading.Thread(target = SendMessage, args = (ClientSock, None))

        thread_4 = threading.Thread(target = RecvMessage, args = (ClientSock, None))

        thread_3.start()

        thread_4.start()

if __name__ == '__main__':

    main()
