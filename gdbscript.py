import gdb


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
        # Alloc fake struct
        msg = gdb.execute(f"call malloc({self.size})", to_string=True)
        assert(msg != None)
        fakeStructPtr = int(msg.strip().split(" ")[-1], 16)

        try:
            gdb.execute(f"set {self.name} = {fakeStructPtr}")
        except:
            return
        inferior = gdb.inferiors()[0]
        inferior.write_memory(fakeStructPtr + off, val)

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
    
    def doCorruption(self):
        # Search valid arg
        for arg in self.args:
            if arg.name not in self.targetStructs:
                continue
            if arg.val == "0x0":
                continue

            # Start corrupt data
            for i in range(0, arg.size, arg.size):
                # Attempt to corrupt data
                gdb.execute("checkpoint")
                gdb.execute("restart 1")

                gdb.execute("info args")
                arg.setVal("A" * arg.size, i)
                gdb.execute("info args")

                finishCurrentFunc()

                # Examine if crash happens
                msg = gdb.execute("info checkpoints", to_string=True)
                assert(msg != None)
                if "No checkpoints" in msg.strip():
                    crashHandler(self.name, arg.name, i)
                    continue
        
                # Restore normal execution routine
                gdb.execute("restart 0")
                gdb.execute("delete checkpoint 1")
    
def stopHandler(event):
    if hasattr (event, 'stop_signal'):
        gdb.execute("continue")

def gdbSetup(brkp, argv):
    gdb.execute(f"start {argv}")
    # TODO: do better on breaking user calls
    gdb.rbreak(f"{brkp}")
    gdb.events.stop.connect(stopHandler)
    gdb.execute("continue")


def finishCurrentFunc():
    gdb.execute("disable")
    gdb.execute("finish")
    gdb.execute("enable")

def crashHandler(func, arg, off):
    with open("Crash_Funcs.txt", "a") as f:
        f.write(f"{func} - {arg} - {off}\n")

# Main logic 
def main():
    # Parameters for libpng
    # targetStructs = ["png_ptr", "info_ptr"]
    # brkp = "^png_"
    # argv = ""

    # Parameters for libjpeg
    targetStructs = ["cinfo"]
    brkp = "^jpeg_"
    argv = "-dct int -ppm -outfile testout.ppm  ./testorig.jpg"

    gdbSetup(brkp, argv)

    while(True):
        funcName = gdb.selected_frame().function()
        userCall = UserCall(funcName, targetStructs)
        userCall.doCorruption()
        gdb.execute(f"clear {funcName}")

        # Continue to next breakpoint
        finishCurrentFunc()
        gdb.execute("continue")


# Main logic starts here
main()