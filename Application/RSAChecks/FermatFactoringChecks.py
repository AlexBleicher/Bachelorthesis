import math
import gmpy2

#TODO: Test with valid Fermat Keys.

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
    n = key._key.keymaterial.n
    tries = 100
    a = gmpy2.isqrt(n)
    c = 0
    while not gmpy2.is_square(a ** 2 - n):
        a += 1
        c += 1
        if c > tries:
            return False
    bsq = a ** 2 - n
    b = gmpy2.isqrt(bsq)
    p = a + b
    q = a - b
    if(p*q==n):
        output.write("{\n")
        output.write("Name of Weakness: Fermat Factoring Algorithm\n")
        output.write(
            "Description: The RSA Modulus can be factored efficiently with Fermat's Factoring Algorithm because p and q are too close together\n")
        output.write(
            "Countermeasure: Use a new RSA key pair that has been generated with a correct implementation of RSA\n")
        output.write("}\n")
