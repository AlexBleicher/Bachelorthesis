import cmd
import json
import os
from KeyParser import *
from KeyLengthAnalyzer import *
from Application.RSAChecks.RSAAnalyzer import *
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
        exit = False #TODO: Make this better. Give User some values to choose from.
        while not exit:
            print("Current Settings: " + str(self.settings))
            print("To Alter Settings input 'alter'. If you want to exit the settings, "
                  "input 'exit' \n")
            userInput = input()
            if userInput == "exit":
                exit = True
            elif userInput == "alter":
                print("Please enter the name of the setting you want to change. \n")
                userInput = input()
                if userInput == "exit":
                    exit=True
                elif userInput not in self.settings:
                    print("Unknown setting " + userInput)
                else:
                    print("Please enter the value you wish to change the setting to.\n")
                    settingName = userInput
                    setting = self.settings[settingName]
                    userInput = input()
                    try:
                        type(setting)(userInput)
                        self.settings[settingName] = userInput
                        json.dump(self.settings, open("settings.json", "w"))
                    except Exception as e:
                        print("Uncompatible Types.\n")

            else:
                print("Unknown command. To Alter Settings input 'alter'. If you want to exit the settings, input 'exit' \n")

    def do_quit(self, arg):
        """Exit the CLI."""
        print("Goodbye")
        return True

if __name__ == '__main__':
    MyApp().cmdloop()