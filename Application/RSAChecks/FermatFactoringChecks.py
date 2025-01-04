import math


def fermatFactoringCheckPrivateKey(key, output, passphrase, settings):
    with key.unlock(passphrase):
        p = key._key.keymaterial.p
        q = key._key.keymaterial.q
        if p > q:
            diff = p - q
        else:
            diff = q - p
        effectiveLengthToCheck = settings["FermatFactoringEffectiveLengthToCheck"]
        if diff < math.pow(2, effectiveLengthToCheck):
            output.write("{\n")
            output.write("Name of Weakness: Fermat Factoring Algorithm\n")
            output.write(
                "Description: The RSA Modulus can be factored efficiently with Fermat's Factoring Algorithm because p and q are too close together\n")
            output.write(
                "Countermeasure: Use a new RSA key pair that has been generated with a correct implementation of RSA\n")
            output.write("}\n")


def fermatFactoringCheckPublicKey(key, output):
    return False
