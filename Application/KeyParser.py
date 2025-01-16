from pgpy import PGPKey
from prompt_toolkit import prompt

def parse_Key(file_path, output):
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
        "format": None,
        "key": None,
        "passphrase": None,
        "algorithm": None
    }
    try:
        # Read the key file
        with open(file_path, "rb") as f:
            key_data = f.read()

        # Try to parse it as ASCII-armored
        try:
            key, _ = PGPKey.from_blob(key_data.decode("utf-8"))
            key_info["format"] = "ASCII Armor"
            key_info["key"] = key
        except Exception:
            # If decoding as UTF-8 fails, treat it as binary
            key, _ = PGPKey.from_blob(key_data)
            key_info["format"] = "Binary"
            key_info["key"] = key

        key_info["algorithm"] = key.key_algorithm.name
        # Determine if the key is public or private
        if key.is_public:
            key_info["is_public"] = True
            key_info["is_private"] = False
        else:
            key_info["is_public"] = False
            key_info["is_private"] = True
            print("Please enter the passphrase to unlock the given key")
            key_info["passphrase"] = input()

        if key.expires_at is None:
            expirationDate = "Never"
        else:
            expirationDate = key.expires_at

        output["Keyfile"] = file_path
        genInfo = {}
        genInfo["Protocol"] = key.key_algorithm.name
        genInfo["Secret Key"] = key_info["is_private"]
        genInfo["Expiration Date"] = str(expirationDate)
        output["General Key Information"] = genInfo
        return key_info

    except Exception as e:
        print(f"Error parsing PGP key: {e}")
        return None
