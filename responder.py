import numpy as np
import socket
from pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
import pickle
import random

print("######################################")                                             
print("####### BEGINING BOB'S SESSION #######") 
print("######################################")  


def verifyMAC(code,key,message):

    h = hmac.HMAC(str(key).encode(),hashes.SHA256())
    h.update(message)
   # h_copy = h.copy()
    #vsig = h.verify(code)
    vsig = h.finalize()
    if(code.__eq__(vsig)):
        return 1
    else:
        return 0
    

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


def get_mKey(psk,secState,label):
    mKey = PRF(PRF(psk,secState),label)
    return mKey


def responder_setup():
        psk = int(get_PSK())
        secState = int(get_SecState())
        label_a = 100001 ##Not sure how to gain this information in real setting
        mkey = get_mKey(psk,secState,label_a)
        return psk, secState, mkey

###Fix when sure we want to use an ASE key or change accoridingly
def ASE_keyGen():
    key = random.randrange(0,10000000)
    key = str(key).encode()
    return key 

def KEM_classic(public_key,encryption):
    cipher_k = 0
    if encryption.__eq__("rsa512"):
        k = ASE_keyGen()
        print(k)
        cipher_k = public_key.encrypt(k,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
    return cipher_k


def KEM_quantum(public_key,encryption):
    cipher_k = 0
    if encryption.__eq__("mceliece8192128"):
        k = ASE_keyGen()
        cipher_k, plain_k = encrypt(public_key)
        print("Quantum key plain: ", plain_k)
        print("Quantum key cipher: ", cipher_k)
    return cipher_k




def contact():

    HOST = "127.0.0.1"  # The server's hostname or IP address
    PORT = 65431  # The port used by the server
    packet_size = 1024

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("\n\nConnecting to Alice...")
      #  s.sendall("Thank you for connecting, Alice".encode())

        print("Recieving m0, tau0")
        
        data = []
        while True:
            packet = s.recv(packet_size)
            #if not packet: break
            if len(packet) < packet_size:
                if len(packet) > 0:
                    data.append(packet)
                break
            data.append(packet)
        print("Finished recieving m0, tau0")
        recv = pickle.loads(b"".join(data))
        
        m0 = recv[0]
        tau0 = recv[1]

        psk, secState, mkeyA = responder_setup()

        if(verifyMAC(tau0,mkeyA,m0) == 1):
           # s.sendall("Verifcation Success".encode())
            print("Verifcation Success")
        else:
         #   s.sendall("Verification Failure".encode())
            print("Verifcation Failure")

        m0 = pickle.loads(m0)
        headerA = m0[0]
        role = headerA[0]
        version = headerA[1]
        label_A = headerA[2] ##may need to be moved to fix verifcation process order.
        public_key_quantum_A = m0[1]
        public_key_classic_A = serialization.load_pem_public_key(m0[2])

        classic_k_cipher = KEM_classic(public_key_classic_A,version[0])
        quantum_k_cipher = KEM_quantum(public_key_quantum_A,version[1])
        print("Sending m1, tau1")

        response = classic_k_cipher
        response = pickle.dumps(response)

        s.sendall(response)
        print("Finished sending m1, tau1")

        s.close()


if __name__ == '__main__':

    contact()