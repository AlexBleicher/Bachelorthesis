import cmd
import warnings

from Application.GeneralChecks.DeprecatedKeyVersionCheck import *
from Application.GeneralChecks.KeyLengthAnalyzer import *
from Application.RSAChecks.RSAAnalyzer import *
from Application.Settings.AlterSettings import *
from Application.KeyParser import *

warnings.filterwarnings("ignore")


class MyApp(cmd.Cmd):
    prompt = '>>'
    intro = "Welcome to my Key Analyzer"

    def __init__(self, settings):
        super().__init__()
        self.settings = settings

    def analyzeKeyFromFile(self, keyfile):
        output = {}
        key_info = parseKey(keyfile, output)
        if key_info is None:
            print("Error parsing key from file: " + keyfile)
            return None
        analyzeKeyLengths(key_info["key"], output, self.settings)
        checkKeyVersion(key_info["key"], output, self.settings)
        if key_info["algorithm"] in RSAAlgorithmIDs:
            analyzeRSAWeaknesses(key_info, keyfile, output, self.settings)
        return output

    def do_analyze(self, arg):
        """Analyze a given Keyfile for possible Vulnerabilities"""
        output = {}
        try:
            if arg == "":
                print("Please enter a Keyfile to analyze.")
                arg = input()
            print("Analyzing the given Keyfile. This could take some time please stand by.")
            keyfile = arg
            output = self.analyzeKeyFromFile(keyfile)
            if output is not None:
                outputDir = input("Please enter the directory to save the output files: ").strip()
                path = os.path.join(outputDir, "output.json")
                if os.path.exists(path):
                    print("Warning: Output file already exists, will overwrite it")
                    os.remove(path)
                json.dump(output, open(path, 'w'), indent=4)
                print("Analysis complete. The result can be found under " + path)
            else:
                print("Analysis failed")
        except Exception as e:
            print("Exception occured: " + str(e))

    def do_analyzedir(self, arg):
        """Analyze every File in a Directory full of Keyfiles for possible Vulnerabilities"""
        output = []
        try:
            if arg == "":
                print("Please enter a directory to analyze.")
                arg = input()
            print("Analyzing all Keyfiles in the given directory. This could take some time please stand by.")
            for keyfile in os.listdir(arg):
                filepath = os.path.join(arg, keyfile)
                outputForKey = self.analyzeKeyFromFile(filepath)
                if outputForKey is not None:
                    output.append(outputForKey)
            if len(output)>0:
                outputDir = input("Please enter the directory to save the output files: ").strip()
                path = os.path.join(outputDir, "output.json")
                if os.path.exists(path):
                    print("Warning: Output file already exists, will overwrite it")
                    os.remove(path)
                json.dump(output, open(path, 'w'), indent=4)
                print("Analysis complete. The result can be found under " + path)
            else:
                print("Analysis failed. No parseable key was found.")
        except Exception as e:
            print("Exception occured: " + str(e))

    def do_settings(self, arg):
        """Display and alter Settings for Vulnerability Checks"""
        calledSettings(input)
        self.settings = json.load(open('settings.json'))

    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True


if __name__ == '__main__':
    settings = json.load(open("settings.json"))
    MyApp(settings).cmdloop()
