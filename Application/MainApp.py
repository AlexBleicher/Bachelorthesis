import cmd
import json
import os
from KeyParser import *
from KeyLengthAnalyzer import *
class MyApp(cmd.Cmd):
    prompt = '>>'
    intro = "Welcome to my Key Analyzer"
    keyfile = ""
    settings = json.load(open('settings.json'))
    def do_analyze(self, arg):
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
            analyzeKeyLengths(key_info["key"], output)
        except Exception as e:
            print("Exception occured: " + str(e))
    def do_settings(self, arg):
        print(self.settings)
    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True

if __name__ == '__main__':
    MyApp().cmdloop()