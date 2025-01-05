from Application.RSAChecks.FermatFactoringChecks import *
from Application.RSAChecks.LowPrivateExponentRSAChecks import *
from Application.RSAChecks.LowPublicExponentRSACheck import *
def analyzeRSAWeaknesses(key_info, output, settings):
    isPrivate = key_info[('is_private')]
    key = key_info['key']
    output.write("Found Weaknesses:\n")
    output.write("------------------\n")
    if settings["RFCVersion"] == "RFC4880":
        output.write("{\n")
        output.write("Name of Weakness: PKCS1-v1.5 padding, Bleichenbacher attacks\n")
        output.write(
            "Description: Using the PKCS1-v1.5 padding (which is the specified padding for OpenPGP implementations of RFC4880) enables the Bleichenbacher attack. Sending adaptively chosen ciphers to an encryption oracle that tells if a given cipher is PKCS1-v1.5 conform allows attackers to limit the space of the possible messages until only the original message is left thus breaking the encryption. This attack could also be applied to signatures.\n")
        output.write(
            "Countermeasure: Implementation of a different padding, restricting access to an encryption oracle or using a different encryption or signature algorithm.\n")
        output.write("}\n")
    elif settings["RFCVersion"] == "RFC9580":
        output.write("{\n")
        output.write("Name of Weakness: Deprecated Algorithm RSA\n")
        output.write(
            "Description: The RSA encryption or signature algorithm is deprecated in RFC9580 due to its usage of the PKCS1-v1.5 padding algorithm that allowed Bleichenbacher attacks. No new Keys for RSA should be generated.\n")
        output.write(
            "Countermeasure: Using a different algorithm.\n")
        output.write("}\n")

    if settings["LowPublicExponentCheckIncluded"]:
        checkLowPublicExponent(key, output, settings)

    if isPrivate:
        passphrase = key_info["passphrase"]
        if settings["FermatFactoringCheckIncluded"]:
            fermatFactoringCheckPrivateKey(key, output, passphrase, settings)
        if settings["LowPrivateExponentCheckIncluded"]:
            checkForLowPrivateExponent(key, output, passphrase, settings)
    else:
        if settings["FermatFactoringCheckIncluded"]:
            fermatFactoringCheckPublicKey(key, output)
