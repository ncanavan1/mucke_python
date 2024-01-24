import numpy as np
import socket
from pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
import random
import pickle
import time

print("######################################")
print("##### BEGINING ALICE'S SESSION #######")
print("######################################")



################################################
###### Basic Connection Set up #################

def contact(message):

    HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
    PORT = 65431  # Port to listen on (non-privileged ports are > 1023)
    packet_size = 1024

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("\n\nWaiting for connection...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
           # while True:
            print("Sending m0, tau0")
            conn.sendall(message)
            #    break
            print("Finished sending m0, tau0")

            #conn.sendall(bytes("\00",'ascii'))
            

           # print(conn.recv(packet_size).decode())

            print("Recieving m1, tau1")
            data = []
            while True:
                packet = conn.recv(1024)
               # if not packet: break
                if len(packet) <=0: break
                data.append(packet)
            print("Finished recieving m1, tau1")
            classic_cipher_B = pickle.loads(b"".join(data))
            
            classical_sym_key = classical_decaps(classic_cipher_B, private_key_classic)
            print(classical_sym_key)
            conn.close()


def classical_decaps(cipher, private_key):
    private_key = serialization.load_pem_private_key(private_key,password=None)
    key = private_key.decrypt(cipher,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
    return key

#################################################
####### Inititator Phase, KeyGen ################
        

def class_KEY_GEN():

    privateKey = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    publicKey = privateKey.public_key()
    privateKey = privateKey.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
    publicKey = publicKey.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return privateKey, publicKey


def quant_key_GEN():
    publicKey, privateKey = generate_keypair()
    return privateKey, publicKey

def gen_m0(headerA,qpk,cpk):
    message = [headerA, qpk, cpk]
    message_serial = pickle.dumps(message)
    return message_serial

def PRF(inpt1,inpt2):
    combined = inpt1 ^ inpt2
    random.seed(combined)
    result = random.randint(0,10000)
    return result

def get_PSK():
    f = open("psk.txt","r")
    psk = f.read()
    f.close()
    return psk

def get_SecState():
    f = open("secstate.txt","r")
    secState = f.read()
    f.close()
    return secState


def mKey(psk,secState,label):
    mA = PRF(PRF(psk,secState),label)
    return mA

#def gen_MAC(m1,m2):
#    m1byte = str(m1).encode()
#    digest = hmac.new(m1byte,m2,hashlib.sha1)
#    return digest

def gen_MAC(key,message):
    h = hmac.HMAC(str(key).encode(),hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature


if __name__ == '__main__':

    psk = int(get_PSK())
    secState = int(get_SecState())
    
    ##header info##
    role = "initiator"
    version = ["rsa512","mceliece8192128"]
    label_a = 100001
    headerA = [role, version, label_a]

    ##Key Generation##
    private_key_classic, public_key_classic = class_KEY_GEN()
    private_key_quant, public_key_quant = quant_key_GEN()



    m0 = gen_m0(headerA,public_key_quant,public_key_classic)
  
    ##Authentication section##
    mKeyA = mKey(psk,secState,label_a)
    tau0 = gen_MAC(mKeyA,m0)

    print(tau0)

    inital_message = pickle.dumps([m0,tau0])
    contact(inital_message)


    ##verify hmac##
"""
    h = hmac.HMAC(str(mKeyA).encode(),hashes.SHA256())
    h.update(m0)
    h_copy = h.copy()
    vsig = h.verify(tau0)
    if(tau0.__eq__(vsig)):
        print("Verification passed")
    else:
        print("Verification failed")
"""

    
    