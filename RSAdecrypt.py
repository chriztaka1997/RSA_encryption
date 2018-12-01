import base64
import json
from GetKeys import *
from os import walk,path, urandom,remove
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa



#This method is the same as MyDecryptMAC(EncryptionInfo)
#For the purpose of RSA, we created a new method with the parameter that we wanted
def MyDecryptRSA(C,IV,tag,ext,EncryptKey,HmacKey):

        #Ask angel about this
        ct = C#cypher text
        iv = IV#initialize vector
        tag =tag#hash
        Enckey= EncryptKey#encryption
        HMACKey = HmacKey#hash key
        extension = ext#extension
        #########

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


def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):
    # load rsa keys
    RSA_Keys = GetPrivateandPublicKey(RSA_Privatekey_filepath)
    # get priveate rsa key
    RSA_Private_Key = RSA_Keys[0]
    # get the concatenated key, which includes encrypt and HMAC key
    key = RSA_Private_Key.decrypt(RSACipher, rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                                                              algorithm=hashes.SHA256(), label=None))

    # second remeber our key is encrykey and hmackey
    EncryptKey, HmacKey = key[:int(len(key) / 2)], key[int(len(key) / 2):]

    # use this these two keys to decrypt our file
    message = MyDecryptRSA(C, IV, tag, ext, EncryptKey, HmacKey)  # orginal
    return message


def jsonDecry(Directory_Path):
    RSA_Path = './'  # curren directory
    listOfFiles = []  # list to hold the file names
    # get all file name from current directory and sub directories
    for (dirpath, dirnames, filenames) in walk(Directory_Path):
        for filename in filenames:
            filePath = path.join(dirpath, filename)
            file = filename.split(".")
            textFile = path.join(dirpath, file[0] + ".txt")  # new text file
            # We can not decrypt files that are not encrypted such as hidden files
            try:
                # load encryption information from json files
                with open(filePath, 'r') as fd:
                    encryptFile = json.load(fd)
                    # after we load the json file delete them
                    remove(filePath)
                    # encode string back to byte format
                    RSAC = base64.decodebytes(encryptFile["RSA_ciphertext"].encode('ascii'))
                    C = base64.decodebytes(encryptFile['AES_ciphertext'].encode('ascii'))
                    IV = base64.decodebytes(encryptFile['IV'].encode('ascii'))
                    TAG = base64.decodebytes(encryptFile['tag'].encode('ascii'))
                    ext = base64.decodebytes(encryptFile['ext'].encode('ascii'))
                    # pass Encryted information to decryption to get original content and
                    # create the file, write to file
                    with open(textFile, 'w') as fb:
                        fb.write(str(MyRSADecrypt(RSAC, C, IV, TAG, ext, RSA_Path), 'UTF8'))
            except:

                print("file was not choosen for encryption/Decryption")
