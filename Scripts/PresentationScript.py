from pgpy import PGPKey
import warnings
warnings.filterwarnings("ignore") #Just to make it look pretty

def parse_basicInfo_Key(file_path):
    """
    Parses a PGP key file to determine its type and format.
    Args:
        file_path (str): Path to the PGP key file.
    Returns:
        dict: Information about the key type and format.
    """
    key_info = {
        "is_public": None,
        "is_private": None,
        "format": None
    }
    try:
        # Read the key file
        with open(file_path, "rb") as f:
            key_data = f.read()

        # Try to parse it as ASCII-armored
        try:
            key, _ = PGPKey.from_blob(key_data.decode("utf-8"))
            key_info["format"] = "ASCII Armor"
        except Exception:
            # If decoding as UTF-8 fails, treat it as binary
            key, _ = PGPKey.from_blob(key_data)
            key_info["format"] = "Binary"

        # Determine if the key is public or private
        if key.is_public:
            key_info["is_public"] = True
            key_info["is_private"] = False
        else:
            key_info["is_public"] = False
            key_info["is_private"] = True

        return key_info

    except Exception as e:
        print(f"Error parsing PGP key: {e}")
        return None

def parse_privateKey(file_path, format, password):
    try:
        # Read the key file
        with open(file_path, "rb") as f:
            key_data = f.read()
        if(format == "ASCII Armor"):
            key, _ = PGPKey.from_blob(key_data.decode("utf-8"))
        else:
            key, _ = PGPKey.from_blob(key_data)

        with key.unlock(password):
            print(f"Key Type: {key.key_algorithm.name}")

    except Exception as e:
        print(f"Error parsing PGP key: {e}")

def parse_publicKey(file_path, format):
    with open(file_path, "rb") as f:
        key_data = f.read()
    if(format == "ASCII Armor"):
        key, _ = PGPKey.from_blob(key_data.decode("utf-8"))
    else:
        key, _ = PGPKey.from_blob(key_data)
    print(f"Key Type: {key.key_algorithm.name}")

if __name__ == "__main__":
    # Ensure a file path is provided as an argument
    key_file_path = input("Please enter the path to the PGP key file: ")
    key_info = parse_basicInfo_Key(key_file_path)
    if key_info is None:
        print("Invalid PGP key file")
    elif key_info["is_private"]:
        password = input("Please enter password for private key: ")
        parse_privateKey(key_file_path, key_info["format"], password)
    else:
        parse_publicKey(key_file_path, key_info["format"])