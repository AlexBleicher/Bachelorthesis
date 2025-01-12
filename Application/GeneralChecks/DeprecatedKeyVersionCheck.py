def checkKeyVersion(key, output, settings):
    version = key._key.header.version
    print(version) #Version 2 and 3 are deprecated since 1998. Version 4 deprecated since RFC 9580