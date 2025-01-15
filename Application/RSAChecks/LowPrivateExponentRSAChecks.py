import math
from Application.Util.CreateWeaknessJSON import *
def checkForLowPrivateExponent(key, foundWeaknesses, passphrase, settings):
    with key.unlock(passphrase):
        d = key._key.keymaterial.d
        n = key._key.keymaterial.n
        boundToCheck = settings["LowPrivateExponentBound"]
        boundApplicable = True
        if boundToCheck == "Estimated Bound":
            bound = math.sqrt(n)
        elif boundToCheck == "Boneh and Durfee Bound":
            bound = math.pow(n, 0.292)
            nToAdd = n ** 0.875
            e = key._key.keymaterial.e
            upperEBound = e / n
            boundApplicable = upperEBound < nToAdd

        if boundApplicable and d < bound:
            foundWeaknesses.append("Low private Exponent",
                                   "A low private Exponent in the RSA Algorithm can lead to the recovery of the private exponent d using Wieners attack or Coppersmiths technique.",
                                   "Use a private Exponent that exceeds half the bit length of the common modulus.")