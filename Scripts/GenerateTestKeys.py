from Crypto.PublicKey import RSA
import pgpy
from pgpy.constants import KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


def read_pem_key(file_path):
    """
    Reads an RSA PEM key file and extracts cryptographic parameters.

    Args:
        file_path (str): Path to the PEM key file.

    Returns:
        dict: Dictionary containing the RSA key parameters.
    """
    try:
        with open(file_path, "rb") as f:
            key = RSA.import_key(f.read())
        return key
    except Exception as e:
        print(e)

def generateOpenPGPKey(key_data, testFileName):
    pgp_key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, key_data.n.bit_length())
    #n = pgpy.packet.types.MPI(key_data.n)
    pgp_key._key.keymaterial.n = pgpy.packet.types.MPI(key_data.n)
    pgp_key._key.keymaterial.e = pgpy.packet.types.MPI(key_data.e)
    pgp_key._key.keymaterial.d = pgpy.packet.types.MPI(key_data.d)
    pgp_key._key.keymaterial.p = pgpy.packet.types.MPI(key_data.p)
    pgp_key._key.keymaterial.q = pgpy.packet.types.MPI(key_data.q)
    pgp_key._key.keymaterial.u = pgpy.packet.types.MPI(key_data.invq)

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
    testFileName = input("Enter the Name of the test key file: ").strip()
    # Read the PEM key and display its data
    key_data = read_pem_key(pem_file)
    if key_data:
        generateOpenPGPKey(key_data, testFileName)
