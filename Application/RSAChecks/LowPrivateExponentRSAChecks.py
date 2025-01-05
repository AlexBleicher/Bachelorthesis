import math
def checkForLowPrivateExponent(key, output, passphrase, settings):
    with key.unlock(passphrase):
        d = key._key.keymaterial.d
        n = key._key.keymaterial.n
        boundToCheck = settings["LowPrivateExponentBound"]
        boundApplicable = True
        if boundToCheck == "Estimated Bound":
            bound = math.sqrt(n)
        elif boundToCheck == "Boneh and Durfee Bound":
            bound = math.pow(n, 0.292)
            boundApplicable = key._key.keymaterial.e < math.pow(n, 1.875)

        if boundApplicable and d < bound:
            output.write("{\n")
            output.write("Name of Weakness: Low private Exponent\n")
            output.write(
                "Description: A low private Exponent in the RSA Algorithm can lead to the recovery of the private exponent d using Wieners attack or Coppersmiths technique.\n")
            output.write(
                "Countermeasure: Use a private Exponent that exceeds half the bit length of the common modulus.\n")
            output.write("}\n")