from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pgpy
from pgpy.constants import KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


def read_pem_key(file_path, isprivate):
    """
    Reads an RSA PEM key file and extracts cryptographic parameters.

    Args:
        file_path (str): Path to the PEM key file.

    Returns:
        dict: Dictionary containing the RSA key parameters.
    """
    try:
        with open(file_path, "rb") as f:
            if isprivate:
                key = serialization.load_pem_private_key(f.read())
            else:
                key = serialization.load_pem_public_key(f.read())
        return key
    except Exception as e:
        print(e)

def generateOpenPGPKey(key_data, isPrivate, testFileName):
    #n = pgpy.packet.types.MPI(key_data.n)
    publicNumbers = key_data.public_numbers()
    pgp_key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, publicNumbers.n.bit_length())
    pgp_key._key.keymaterial.e = pgpy.packet.types.MPI(publicNumbers.e)
    pgp_key._key.keymaterial.n = pgpy.packet.types.MPI(publicNumbers.n)
    if isPrivate:
        privateNumbers = key_data.private_numbers
        pgp_key._key.keymaterial.d = pgpy.packet.types.MPI(privateNumbers.d)
        pgp_key._key.keymaterial.p = pgpy.packet.types.MPI(privateNumbers.p)
        pgp_key._key.keymaterial.q = pgpy.packet.types.MPI(privateNumbers.q)

    #uidCreated = pgpy.PGPUID.new("TestyMcTestface", email="TestyMcTestface@gmail.com")
    #pgp_key.add_uid(uid=uidCreated)
    #pgp_key.protect("test", pgpy.constants.SymmetricKeyAlgorithm.AES256, pgpy.constants.HashAlgorithm.SHA256)

    with open(testFileName + ".gpg", "wb") as f:
        f.write(bytes(pgp_key))
    with open(testFileName + ".asc", "w") as f:
        f.write(str(pgp_key))

if __name__ == "__main__":
    # Prompt the user for the PEM key file path
    pem_file = input("Enter the path to the PEM key file: ").strip()
    isPrivate = input("Is Private key: ").strip() == "true"
    testFileName = input("Enter the Name of the test key file: ").strip()
    # Read the PEM key and display its data
    key_data = read_pem_key(pem_file, isPrivate)
    if key_data:
        generateOpenPGPKey(key_data, isPrivate, testFileName)
