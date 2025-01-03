import cmd
import json
from KeyParser import *
from KeyLengthAnalyzer import *
class MyApp(cmd.Cmd):
    prompt = '>>'
    intro = "Welcome to my Key Analyzer"
    keyfile = ""
    settings = json.load(open('settings.json'))
    def do_analyze(self, arg):
        print("Analyzing the given Keyfile. This could take some time please stand by.")
        self.keyfile = arg
        key_info = parse_Key(self.keyfile)
        analyzeKeyLengths(key_info["key"])
    def do_settings(self, arg):
        print(self.settings)
    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True

if __name__ == '__main__':
    MyApp().cmdloop()