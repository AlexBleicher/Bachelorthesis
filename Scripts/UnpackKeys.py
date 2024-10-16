import gnupg
import sys

def parse_pgp_key(key_data):
    # Initialize the GnuPG instance
    gpg = gnupg.GPG()

    # Import the key into GnuPG
    import_result = gpg.import_keys(key_data)

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
        print(f"Algorithm: {key['algo']}")
        print(f"Creation Date: {key['date']}")
        print(f"Length: {key['length']} bits")
        print(f"User IDs: {', '.join(key['uids'])}")
        print(f"Fingerprint: {key['fingerprint']}")
        print("Subkeys:")
        for subkey in key['subkeys']:
            print(f"  Subkey ID: {subkey['keyid']}, Length: {subkey['length']} bits, Expires: {subkey['expires']}, Algorithm: {subkey['algo']}")
        print()

if __name__ == "__main__":
    # Prompt the user to enter the path to the PGP key file
    key_file_path = input("Please enter the path to the PGP key file: ")

    # Read the PGP key file
    try:
        with open(key_file_path, 'r') as key_file:
            key_data = key_file.read()
    except FileNotFoundError:
        print(f"Error: File '{key_file_path}' not found.")
        sys.exit(1)

    # Parse the PGP key
    parse_pgp_key(key_data)
