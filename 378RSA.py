import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes, hmac
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def MyencryptMAC(message,EncKey,HMACKey):
	backend = default_backend()
	padder = padding.PKCS7(128).padder() #set up padding
	padded_data = padder.update(message) + padder.finalize() #padding = setUP + remainder
	iv = os.urandom(16) # initialize vector
	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend) # Cipher objects combine an algorithm such as AES with a mode like CBC or CTR
	encryptor = cipher.encryptor() # set up encryption block
	ct = encryptor.update(padded_data) + encryptor.finalize()#create cipher text
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #HASH Generated
	h.update(ct)#pass cypher text into hash
	return ct,iv,h.finalize() #return cypher text, initialize vector, hash

def MyfileEncryptMAC(filepath):
    HMACKey = os.urandom(32) # generate 32byte secret key
    EncKey = os.urandom(32) #Generate encryption key
    days_file = open(filepath,'rb') #open file and read string
    extension = filepath.split(".") # seperate the file name from extension
    extension = extension[1]
    with open(filepath,'rb') as binary_file: #read file in bytes
            data = binary_file.read() #Read the whole file at once
    answer = MyencryptMAC(data,EncKey,HMACKey) #pass message,key
    return answer,EncKey,HMACKey,extension #return cypher, iv, hash, encryption key, hash key


def MyDecryptMAC(EncryptionInfo):
        ct = EncryptionInfo[0][0]#cypher text
        iv = EncryptionInfo[0][1]#initialize vector
        tag =EncryptionInfo[0][2]#hash
        Enckey= EncryptionInfo[1]#encryption
        HMACKey = EncryptionInfo[2]#hash key
        extension = EncryptionInfo[3]#extension
        backend = default_backend()
        cipher = Cipher(algorithms.AES(Enckey), modes.CBC(iv),backend=backend)#Setting up cypher
        h = hmac.HMAC(HMACKey,hashes.SHA256(), backend=default_backend())#Setting up hash
        h.update(ct)#pass cypher text to hash
        try:
                print("MY FILEVerify:", h.verify(tag))#verify match break except V
                decryptor = cipher.decryptor()#setupdecryption box
                data = decryptor.update(ct) +decryptor.finalize() #decrypt
                unpadder = padding.PKCS7(128).unpadder()
                message = unpadder.update(data) +unpadder.finalize()#pad the decryption
                return message
        except:
                print("anything")     

#Load private key
def LoadPrivateKey(RSA_private_key_path):
    with open(RSA_private_key_path, "rb") as Private_key_file:
        private_key = serialization.load_pem_private_key(Private_key_file.read(), password=None,
                                                         backend=default_backend())

    Private_key_file.close()  # close
    return private_key

#load public key
def LoadPublicKey(RSA_public_key_path):
    # read public key
    with open(RSA_public_key_path, "rb") as Public_key_file:
        public_key = serialization.load_pem_public_key(Public_key_file.read(), backend=default_backend())

    Public_key_file.close()  # close
    return public_key


#gets the private and public key from a file
#if the file does not exist, creates private and public key file
def GetPrivateandPublicKey(RSA_Path):
        #test to see if public & private key files exist, if they do not then create them, and put the files in read and write mode.
        #if they do exist then read 
        RSA_public_key_path = RSA_Path + 'publickey.pem'
        RSA_private_key_path = RSA_Path + 'privatekey.pem'
        private_key_gen = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )


        if(os.path.exists(RSA_private_key_path)):
            #read private key
            #
            # with open(RSA_private_key_path, "rb") as Private_key_file:
            #     private_key = serialization.load_pem_private_key(Private_key_file.read(),password=None,backend=default_backend())
            #
            # Private_key_file.close()#close
            private_key = LoadPrivateKey(RSA_private_key_path)
            
        else:
            #If the path does not exist, it creates a private key
            RSA_Private_Key = open(RSA_private_key_path,'wb+') #create and write mode
            private_key = private_key_gen.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                  encryption_algorithm=serialization.NoEncryption())
            RSA_Private_Key.write(private_key)#write key
            RSA_Private_Key.close()#close
            private_key = LoadPrivateKey(RSA_private_key_path)
            

            
        if(os.path.exists(RSA_public_key_path)):
            #read public key
            # with open(RSA_public_key_path, "rb") as Public_key_file:
            #     public_key= serialization.load_pem_public_key(Public_key_file.read(),backend=default_backend())
            #
            # Public_key_file.close()#close
            public_key = LoadPublicKey(RSA_public_key_path)

        else:
            # If the path does not exist, it creates a public key
            RSA_Public_Key = open(RSA_public_key_path,'wb+')#create and write mode 

            public_key = private_key_gen.public_key()
            public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            RSA_Public_Key.write(public_key)#write key

            RSA_Public_Key.close()#close

            #Get private key and public key in an object format
            public_key = LoadPublicKey(RSA_public_key_path)

        return private_key,public_key


def MyRSAEncrypt(filePath, RSA_Path):
        EncryInfo = MyfileEncryptMAC(filePath) #call file encryption

        RSA_Keys = GetPrivateandPublicKey(RSA_Path) #Get the private and public key

        RSA_Public_Key = RSA_Keys[1]
        key = EncryInfo[1] + EncryInfo[2]
        RSAciphertext = RSA_Public_Key.encrypt(key,rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        return RSAciphertext,EncryInfo[0][0],EncryInfo[0][1],EncryInfo[0][2],EncryInfo[3]

def MyRSADecrypt (RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
        #first we decrypt
        RSA_Keys = GetPrivateandPublicKey(RSA_Path)
        RSA_Private_Key = RSA_Keys[0]
        key = RSA_Private_Key.decrypt(RSACipher,rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

        #second remeber our key is encrykey and hmackey
        EncryptKey, HmacKey = key[:int(len(key)/2)], key[int(len(key)/2):]

        # use this these two keys to decrypt our file
        message = MyDecryptRSA(C,IV,tag,ext,EncryptKey,HmacKey) #orginal

#This method is the same as MyDecryptMAC(EncryptionInfo)
#For the purpose of RSA, we created a new method with the parameter that we wanted
def MyDecryptRSA(C,IV,tag,ext,EncryptKey,HmacKey):
        ct = C#cypher text
        iv = IV#initialize vector
        tag =tag#hash
        Enckey= EncryptKey#encryption
        HMACKey = HmacKey#hash key
        extension = ext#extension
        backend = default_backend()
        cipher = Cipher(algorithms.AES(Enckey), modes.CBC(iv),backend=backend)#Setting up cypher
        h = hmac.HMAC(HMACKey,hashes.SHA256(), backend=default_backend())#Setting up hash
        h.update(ct)#pass cypher text to hash
        try:
                print("MY FILEVerify:", h.verify(tag))#verify match break except V
                decryptor = cipher.decryptor()#setupdecryption box
                data = decryptor.update(ct) +decryptor.finalize() #decrypt
                unpadder = padding.PKCS7(128).unpadder()
                message = unpadder.update(data) +unpadder.finalize()#pad the decryption
                return message
        except:
                print("anything") 


filePath = "./a.png" #path for file
RSA_Path = './'#path for RSA
RSAInfo = MyRSAEncrypt(filePath,RSA_Path)
MyRSADecrypt(RSAInfo[0],RSAInfo[1],RSAInfo[2],RSAInfo[3],RSAInfo[4],RSA_Path)


        
        

