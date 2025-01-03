from pgpy import PGPKey


def parse_Key(file_path):
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
        "key": None
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
