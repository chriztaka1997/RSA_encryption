import json
import base64
from os import walk,path, urandom,remove
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
        #if they do exist then read from the existing file
        RSA_public_key_path = RSA_Path + 'publickey.pem'
        RSA_private_key_path = RSA_Path + 'privatekey.pem'
        private_key_gen = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )

        #if private key exist load else create and save
        if(path.exists(RSA_private_key_path)):
                private_key = LoadPrivateKey(RSA_private_key_path)
            
        else:
            #If the path does not exist, it creates a private key, saves in file, and loads to variable 
            RSA_Private_Key = open(RSA_private_key_path,'wb+') #create and write mode
            private_key = private_key_gen.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                  encryption_algorithm=serialization.NoEncryption())
            RSA_Private_Key.write(private_key)#write key
            RSA_Private_Key.close()#close
            private_key = LoadPrivateKey(RSA_private_key_path)
            

        #if public key exist load else create and save
        if(path.exists(RSA_public_key_path)):
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

        RSA_Public_Key = RSA_Keys[1]# This is the public key
        key = EncryInfo[1] + EncryInfo[2]#This is the encryption and HMAC Keys concatenated
        #create RSA cipher text using public key, encryption + HMAC key, and OAEP padding
        RSAciphertext = RSA_Public_Key.encrypt(key,rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        #this is rsa cipher, cipher, IV, tag, ext
        return RSAciphertext,EncryInfo[0][0],EncryInfo[0][1],EncryInfo[0][2],EncryInfo[3]

def MyRSADecrypt (RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
      
        #load rsa keys
        RSA_Keys = GetPrivateandPublicKey(RSA_Privatekey_filepath)
        #get priveate rsa key
        RSA_Private_Key = RSA_Keys[0]
        #get the concatenated key, which includes encrypt and HMAC key
        key = RSA_Private_Key.decrypt(RSACipher,rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

        #second remeber our key is encrykey and hmackey
        EncryptKey, HmacKey = key[:int(len(key)/2)], key[int(len(key)/2):]

        # use this these two keys to decrypt our file
        message = MyDecryptRSA(C,IV,tag,ext,EncryptKey,HmacKey) #orginal
        return message

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
        
        
def jsonDecry(Directory_Path):
        RSA_Path = './' #curren directory 
        listOfFiles = [] #list to hold the file names
        #get all file name from current directory and sub directories 
        for (dirpath, dirnames, filenames) in walk(Directory_Path):
                for filename in filenames:
                        filePath = path.join(dirpath, filename)
                        file = filename.split(".")
                        textFile = path.join(dirpath,file[0]+".txt") #new text file
                        #We can not decrypt files that are not encrypted such as hidden files 
                        try:
                                #load encryption information from json files
                                 with open(filePath, 'r') as fd:
                                         encryptFile = json.load(fd)
                                         #after we load the json file delete them
                                         remove(filePath)
                                         #encode string back to byte format 
                                         RSAC = base64.decodebytes(encryptFile["RSA_ciphertext"].encode('ascii'))
                                         C = base64.decodebytes(encryptFile['AES_ciphertext'].encode('ascii'))
                                         IV = base64.decodebytes(encryptFile['IV'].encode('ascii'))
                                         TAG = base64.decodebytes(encryptFile['tag' ].encode('ascii'))
                                         ext = base64.decodebytes(encryptFile['ext'].encode('ascii'))
                                         #pass Encryted information to decryption to get original content and
                                         #create the file, write to file 
                                         with open(textFile, 'w') as fb:
                                                
                                                fb.write(str(MyRSADecrypt(RSAC,C,IV,TAG,ext,RSA_Path),'UTF8'))
                        except:
                                
                                print("file was not choosen for encryption/Decryption")
                                

      
                
                
                            
                                
                                
   

Directory_Path = './encrypted_file'#path for file that will encrypted
jsonEncry(Directory_Path)
jsonDecry(Directory_Path)


        
        

