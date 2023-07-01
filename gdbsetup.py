import gdb
import configparser


# Setup the todo function list
def gdbSetup(brkpRegx, argv):
    gdb.execute("set confirm off")
    gdb.execute("set pagination off")
    gdb.execute(f"start {argv}")

    with open("Todo_Funcs.txt", "w") as f:
        for regx in brkpRegx:
            for brkp in gdb.rbreak(f"{regx}"):
                location = brkp.location
                assert location != None
                f.write(f"{location.split(':')[-1]}\n")
    
    gdb.execute("quit")

def readConfig():
    global targetStructs
    global brkpRegx
    global argv

    # Create a ConfigParser object
    config = configparser.ConfigParser()

    # Read the configuration file
    config.read('config.ini')

    target = "work"

    # Access the variables
    targetStructs = config.get(target, 'targetStructs').split(",")
    brkpRegx = config.get(target, 'brkpRegx').split(",")
    argv = config.get(target, 'argv')

# Globals
targetStructs = []
brkpRegx = []
argv = ""

# Main logic 
def main():
    global targetStructs
    global brkpRegx
    global argv

    readConfig()
    gdbSetup(brkpRegx, argv)

main()