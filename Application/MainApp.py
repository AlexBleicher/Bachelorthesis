import cmd
import json
import os
from KeyParser import *
from Application.GeneralChecks.KeyLengthAnalyzer import *
from Application.RSAChecks.RSAAnalyzer import *
from Application.Settings.AlterSettings import *
from Application.GeneralChecks.DeprecatedKeyVersionCheck import *
import warnings

warnings.filterwarnings("ignore")


class MyApp(cmd.Cmd):
    prompt = '>>'
    intro = "Welcome to my Key Analyzer"
    settings = json.load(open('settings.json'))

    def analyzeKeyFromFile(self, keyfile):
        output = {}
        key_info = parse_Key(keyfile, output)
        analyzeKeyLengths(key_info["key"], output, self.settings)
        checkKeyVersion(key_info["key"], output, self.settings)
        if "RSA" in key_info["algorithm"]:
            analyzeRSAWeaknesses(key_info, output, self.settings)
        return output

    def do_analyze(self, arg):
        output={}
        try:
            if arg == "":
                print("Please enter a Keyfile to analyze.")
                arg = input()
            print("Analyzing the given Keyfile. This could take some time please stand by.")
            keyfile = arg
            output = self.analyzeKeyFromFile(keyfile)
            print("Analysis complete. The result can be found under " + os.path.abspath("output.json"))
        except Exception as e:
            print("Exception occured: " + str(e))
        finally:
            if os.path.exists("output.json"):
                os.remove("output.json")
            json.dump(output, open('output.json', 'w'), indent=4)

    def do_analyze_dir(self, arg):
        output = []
        try:
            if arg == "":
                print("Please enter a directory to analyze.")
                arg = input()
            print("Analyzing all Keyfiles in the given directory. This could take some time please stand by.")
            for keyfile in os.listdir(arg):
                output.append(self.analyzeKeyFromFile(keyfile))
            print("Analysis complete. The result can be found under " + os.path.abspath("output.json"))
        except Exception as e:
            print("Exception occured: " + str(e))
        finally:
            if(os.path.exists("output.json")):
                os.remove("output.json")
            json.dump(output, open('open.json', 'w'), indent=4)
    def do_settings(self, arg):
        calledSettings(input)
        self.settings = json.load(open('settings.json'))

    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True


if __name__ == '__main__':
    MyApp().cmdloop()
