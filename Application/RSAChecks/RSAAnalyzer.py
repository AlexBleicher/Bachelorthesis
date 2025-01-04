from Application.RSAChecks.FermatFactoringChecks import *

def analyzeRSAWeaknesses(key_info, output, settings):
    isPrivate = key_info[('is_private')]
    key = key_info['key']
    output.write("Found Weaknesses:\n")
    output.write("------------------\n")
    if isPrivate:
        passphrase = key_info["passphrase"]
        if settings["FermatFactoringCheckIncluded"]:
            fermatFactoringCheckPrivateKey(key, output, passphrase, settings)

    else:
        if settings["FermatFactoringCheckIncluded"]:
            fermatFactoringCheckPublicKey(key, output)
