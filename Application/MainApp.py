import cmd
from KeyAnalyzer import *
class MyApp(cmd.Cmd):
    prompt = '>>'
    intro = "Welcome to my Key Analyzer"
    keyfile = ""
    def do_analyze(self, arg):
        print("Analyzing the given Keyfile. This could take some time please stand by.")
        self.keyfile = arg
        key_info = parse_Key(self.keyfile)
        print(key_info)
    def do_quit(self, line):
        """Exit the CLI."""
        print("Goodbye")
        return True

if __name__ == '__main__':
    MyApp().cmdloop()