import gdb
import configparser


class Argument():
    def __init__(self, name, val):
        self.name = name
        self.val = val
        self.type = None
        self.size = None

        self.getSelfType()
        self.getSelfSize()
    
    def getSelfType(self):
        msg = gdb.execute(f"whatis {self.name}", to_string=True)
        assert(msg != None)
        self.type = msg.strip().split(" ")[-1]

    def getSelfSize(self):
        msg = None
        try:
            msg = gdb.execute(f"print sizeof(*{self.name})", to_string=True)
        except gdb.error:
            self.size = 8
            return

        assert(msg != None)
        self.size = int(msg.strip().split(" ")[-1])
    
    def setVal(self, val, off):
        # Directly modify / corrupt the struct
        inferior = gdb.inferiors()[0]
        try:
            inferior.write_memory(int(self.val, 16) + off, val)
        except gdb.error:
            # Unaccessible
            return

class UserCall():
    def __init__(self, name, targetStructs):
        self.name = name
        self.targetStructs = targetStructs
        self.args = []
        self.getSelfArgs()

    def getSelfArgs(self):
        args = gdb.execute("info args", to_string=True)
        assert(args != None)
        if "No arguments." in args:
            return
        args = args.strip().split("\n")

        for arg in args:
            temp = arg.split(" ")
            argName = temp[0]
            argVal = temp[temp.index("=") + 1]
            self.args.append(Argument(argName, argVal))
    
    def doFullCorrupt(self, arg):
        # Attempt to corrupt data
        gdb.execute("checkpoint")
        gdb.execute("restart 1")

        arg.setVal("A" * arg.size, 0)

        finishCurrentFunc()

        # Examine if crash happens
        msg = gdb.execute("info checkpoints", to_string=True)
        assert(msg != None)
        if "No checkpoints" in msg.strip():
            crashFuncHandler(self.name, arg.name, 0, arg.size)
            return
        
        # Restore normal execution routine
        gdb.execute("restart 0")
        gdb.execute("delete checkpoint 1")
    
    def doOverflow(self, arg, bound):
        for i in range(0, bound, 1):
            # Attempt to corrupt data
            gdb.execute("checkpoint")
            gdb.execute("restart 1")

            arg.setVal("A" * i, 0)

            finishCurrentFunc()

            # Examine if crash happens
            msg = gdb.execute("info checkpoints", to_string=True)
            assert(msg != None)
            if "No checkpoints" in msg.strip():
                crashFuncHandler(self.name, arg.name, 0, i)
                continue
        
            # Restore normal execution routine
            gdb.execute("restart 0")
            gdb.execute("delete checkpoint 1")

    def doArbiWrite(self, arg, len):
        for i in range(0, arg.size, 1):
            # Attempt to corrupt data
            gdb.execute("checkpoint")
            gdb.execute("restart 1")

            arg.setVal("A" * len, i)

            finishCurrentFunc()

            # Examine if crash happens
            msg = gdb.execute("info checkpoints", to_string=True)
            assert(msg != None)
            if "No checkpoints" in msg.strip():
                crashFuncHandler(self.name, arg.name, i, i + len)
                continue
        
            # Restore normal execution routine
            gdb.execute("restart 0")
            gdb.execute("delete checkpoint 1")

    def doCorruption(self, step):
        # Search valid arg
        for arg in self.args:
            if arg.name not in self.targetStructs:
                continue
            if arg.val == "0x0":
                continue

            # Start corrupt data
            if step == -1:
                step = arg.size
            for i in range(0, arg.size, step):
                # Attempt to corrupt data
                gdb.execute("checkpoint")
                gdb.execute("restart 1")

                # Some times the arg's address is unaccessible
                # gdb.execute(f"print *{arg.name}")
                arg.setVal("A" * step, i)
                # gdb.execute(f"print *{arg.name}")

                finishCurrentFunc()

                # Examine if crash happens
                msg = gdb.execute("info checkpoints", to_string=True)
                assert(msg != None)
                if "No checkpoints" in msg.strip():
                    crashFuncHandler(self.name, arg.name, i, i + 1)
                    continue
        
                # Restore normal execution routine
                gdb.execute("restart 0")
                gdb.execute("delete checkpoint 1")

def stopHandler(event):
    if hasattr (event, 'stop_signal'):
        gdb.execute("continue")

def gdbSetup(brkpRegx, argv):
    global workingFuncs
    
    gdb.execute("set confirm off")
    gdb.execute("set pagination off")
    gdb.execute(f"start {argv}")

    for regx in brkpRegx:
        gdb.rbreak(f"{regx}")
    
    # Record todo funcs
    with open("Todo_Funcs.txt", "r") as f:
        todoFuncs = f.read().strip().split("\n")
    
    # Record finished funcs
    with open("Finish_Funcs.txt", "r") as f:
        finishFuncs = f.read().strip().split("\n")
    
    workingFuncs = list(set(todoFuncs) - set(finishFuncs))
    
    gdb.events.stop.connect(stopHandler)
    gdb.execute("continue")


def finishCurrentFunc():
    gdb.execute("disable")
    gdb.execute("finish")
    gdb.execute("enable")

def crashFuncHandler(funcName, arg, off_start, off_end):
    with open("Crash_Funcs.txt", "a") as f:
        f.write(f"{funcName} - {arg} - {off_start} - {off_end}\n")
    
def finishFuncHandler(funcName):
    with open("Finish_Funcs.txt", "a") as f:
        f.write(f"{funcName}\n")

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
workingFuncs = []

# Main logic 
def main():
    global targetStructs
    global brkpRegx
    global argv
    global workingFuncs

    readConfig()
    gdbSetup(brkpRegx, argv)

    while(True):
        try:
            funcName = gdb.selected_frame().function()
            if funcName.name not in workingFuncs:
                userCall = UserCall(funcName, targetStructs)
                userCall.doCorruption(-1)
                finishFuncHandler(funcName)

            # Continue to next breakpoint
            gdb.execute(f"clear {funcName}")
            finishCurrentFunc()
            gdb.execute("continue")
        except gdb.error:
            gdb.execute("quit")


# Main logic starts here
main()