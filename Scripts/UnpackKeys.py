import gnupg
import sys
from datetime import datetime

key_id_to_algorithm = {
    1: "RSA (Encrypt or Sign)",
    2: "RSA Encrypt-Only",
    3: "RSA Sign-Only",
    16: "Elgamal (Encrypt-Only)",
    17: "DSA (Digital Signature Algorithm)",
    18: "ECDH public key algorithm",
    19: "ECDSA public key algorithm",
    20: "Reserved (formerly Elgamal Encrypt or Sign)",
    21: "Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)",
    22: "EdDSA",
    100: "Private/Experimental algorithm",
    101: "Private/Experimental algorithm",
    102: "Private/Experimental algorithm",
    103: "Private/Experimental algorithm",
    104: "Private/Experimental algorithm",
    105: "Private/Experimental algorithm",
    106: "Private/Experimental algorithm",
    107: "Private/Experimental algorithm",
    108: "Private/Experimental algorithm",
    109: "Private/Experimental algorithm",
    110: "Private/Experimental algorithm",
}

def parse_pgp_key(key_data):
    # Initialize the GnuPG instance
    gpg = gnupg.GPG()

    # Import the key into GnuPG
    import_result = gpg.import_keys_file(key_data)

    if not import_result.results:
        print("Error: Failed to import key.")
        sys.exit(1)

    # Fetch the key information
    keys = gpg.list_keys()

    if not keys:
        print("Error: No keys found.")
        sys.exit(1)

    for key in keys:
        print(f"Key ID: {key['keyid']}")
        print(f"Key Type: {key['type']}")
        print(f"Algorithm: {key_id_to_algorithm.get(int(key['algo']))}")
        print(f"Creation Date: {datetime.fromtimestamp(int(key['date']))}")
        print(f"Length: {key['length']} bits")
        print(f"User IDs: {', '.join(key['uids'])}")
        print(f"Fingerprint: {key['fingerprint']}")
        print()

if __name__ == "__main__":
    # Prompt the user to enter the path to the PGP key file
    key_file_path = input("Please enter the path to the PGP key file: ")

    parse_pgp_key(key_file_path)
