keyLifetimesNIST = {
    "Insecure": 111,
    "Secure up to 2030": 112,
    "Secure Beyond 2030": 113
}

keyLifetimesBSI = {
    "Insecure": 119,
    "Secure up to 2030": 120
}

effectiveKeyLengthsBSIClassical = {
    120: 2800,
    128: 3000
}

effectiveKeyLengthsNISTClassical = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: 7680,
    256: 15360
}

effectiveKeyLengthsBSIECC = {
    120: 240,
    128: 250
}

effectiveKeyLengthsNISTECC = {
    80: 160,
    112: 224,
    128: 256,
    192: 384,
    256: 512
}

def analyzeKeyLengths(key):
    keysize = key.key_size
    algorithm = key.key_algorithm.name



