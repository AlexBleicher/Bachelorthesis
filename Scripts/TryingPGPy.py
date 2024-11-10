from pgpy import PGPKey

def parse_pgp_key(file_path):
    try:
        # Load the PGP key from file
        with open(file_path, 'rb') as f:
            key_data = f.read()

        # Parse the PGP key using PGPy
        pgp_key, _ = PGPKey.from_blob(key_data)
        with pgp_key.unlock("test"):
            # Print basic key details
            print("=== PGP Key Details ===")
            #print(f"Key ID: {pgp_key.key_id}")
            print(f"Fingerprint: {pgp_key.fingerprint}")
            print(f"Key Type: {pgp_key.key_algorithm.name}")
            print(f"Creation Date: {pgp_key.created}")
            print(f"Is Public Key: {pgp_key.is_public}")
            # Print algorithm-specific details
            if pgp_key.key_algorithm.name == "RSAEncryptOrSign":
                print("Modulus (n):", pgp_key._key.keymaterial.n)
                print("Public Exponent (e):", pgp_key._key.keymaterial.e)
                if not pgp_key.is_public:
                    debug = pgp_key._key.keymaterial
                    print("Private Exponent (d):", pgp_key._key.keymaterial.d)

            elif pgp_key.key_algorithm.name == "DSA":
                print("Prime (p):", pgp_key._key.keymaterial.p)
                print("Subprime (q):", pgp_key._key.keymaterial.q)
                print("Generator (g):", pgp_key._key.keymaterial.g)
            elif pgp_key.key_algorithm.name == "ECDSA" or pgp_key.key_algorithm.name == "ECDH":
                print("Curve:", pgp_key._key.keymaterial.curve.name)

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Ensure a file path is provided as an argument
    key_file_path = input("Please enter the path to the PGP key file: ")

    parse_pgp_key(key_file_path)
