from os import path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Load private key
def LoadPrivateKey(RSA_private_key_path):
    with open(RSA_private_key_path, "rb") as Private_key_file:
        private_key = serialization.load_pem_private_key(Private_key_file.read(), password=None,
                                                         backend=default_backend())

    Private_key_file.close()  # close
    return private_key


# load public key
def LoadPublicKey(RSA_public_key_path):
    # read public key
    with open(RSA_public_key_path, "rb") as Public_key_file:
        public_key = serialization.load_pem_public_key(Public_key_file.read(), backend=default_backend())

    Public_key_file.close()  # close
    return public_key


# gets the private and public key from a file
# if the file does not exist, creates private and public key file
def GetPrivateandPublicKey(RSA_Path):
    # test to see if public & private key files exist, if they do not then create them, and put the files in read and write mode.
    # if they do exist then read from the existing file
    RSA_public_key_path = RSA_Path + 'publickey.pem'
    RSA_private_key_path = RSA_Path + 'privatekey.pem'
    private_key_gen = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # if private key exist load else create and save
    if (path.exists(RSA_private_key_path)):
        private_key = LoadPrivateKey(RSA_private_key_path)

    else:
        # If the path does not exist, it creates a private key, saves in file, and loads to variable
        RSA_Private_Key = open(RSA_private_key_path, 'wb+')  # create and write mode
        private_key = private_key_gen.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption())
        RSA_Private_Key.write(private_key)  # write key
        RSA_Private_Key.close()  # close
        private_key = LoadPrivateKey(RSA_private_key_path)

    # if public key exist load else create and save
    if (path.exists(RSA_public_key_path)):
        public_key = LoadPublicKey(RSA_public_key_path)

    else:
        # If the path does not exist, it creates a public key
        RSA_Public_Key = open(RSA_public_key_path, 'wb+')  # create and write mode

        public_key = private_key_gen.public_key()
        public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
        RSA_Public_Key.write(public_key)  # write key

        RSA_Public_Key.close()  # close

        # Get private key and public key in an object format
        public_key = LoadPublicKey(RSA_public_key_path)

    return private_key, public_key