import cmd
import json
import os
from KeyParser import *
from KeyLengthAnalyzer import *
from Application.RSAChecks.RSAAnalyzer import *
from Application.Settings.AlterSettings import *

import warnings
warnings.filterwarnings("ignore")
class MyApp(cmd.Cmd):
    prompt = '>>'
    intro = "Welcome to my Key Analyzer"
    keyfile = ""
    settings = json.load(open('settings.json'))
    def do_analyze(self, arg):
        global output
        try:
            if arg == "":
                print("Please enter a Keyfile to analyze.")
                arg = input()
            print("Analyzing the given Keyfile. This could take some time please stand by.")
            if os.path.exists("output.txt"):
                os.remove("output.txt")
            output = open("output.txt", "x")
            self.keyfile = arg
            key_info = parse_Key(self.keyfile, output)
            analyzeKeyLengths(key_info["key"], output, self.settings)
            analyzeRSAWeaknesses(key_info, output, self.settings)
            print("Analysis complete. The result can be found under " + os.path.abspath("output.txt"))
        except Exception as e:
            print("Exception occured: " + str(e))
        finally:
            output.close()
    def do_settings(self, arg):
        calledSettings(input)
        self.settings = json.load(open('settings.json'))

    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True

if __name__ == '__main__':
    MyApp().cmdloop()