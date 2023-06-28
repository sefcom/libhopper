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

def gdbSetup(brkp, argv):
    gdb.execute(f"start {argv}")
    # TODO: do better on breaking user calls
    for regx in brkp:
        gdb.rbreak(f"{regx}")
    
    # Clear finished funcs
    with open("Finish_Funcs.txt", "r") as f:
        funcs = f.read().strip().split("\n")
    for func in funcs:
        gdb.execute(f"clear {func}")
    
    gdb.execute("info breakpoints")
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
    gdb.execute(f"clear {funcName}")
    with open("Finish_Funcs.txt", "a") as f:
        f.write(f"{funcName}\n")

# Main logic 
def main():
    # TODO: Config this before start!
    # Parameters for unit test
    targetStructs = ["state"]
    brkp = ["^libapi_"]
    argv = ""

    # Parameters for libpng
    # targetStructs = ["png_ptr", "info_ptr"]
    # brkp = ["^png_"]
    # argv = ""

    # Parameters for libjpeg
    # targetStructs = ["cinfo"]
    # brkp = ["^jpeg_"]
    # djpeg testing arguments
    # argv = "-dct int -ppm -outfile testout.ppm  ./testorig.jpg"
    # argv = "-dct int -bmp -colors 256 -outfile testout.bmp  ./testorig.jpg"
    # argv = "-dct int -ppm -outfile testoutp.ppm ./testprog.jpg"
    # cjpeg testing arguments
    # argv = "-dct int -outfile testout.jpg  ./testimg.ppm"
    # argv = "-dct int -progressive -opt -outfile testoutp.jpg ./testimg.ppm"
    # jpegtran testing arguments
    # argv = "-outfile testoutt.jpg ./testprog.jpg"

    # Parameters for libxml
    # targetStructs = ["node", "parent", "lst", "target", "elem"]
    # brkp = ["^xml", "^html"]

    # Parameters for zlib
    # targetStructs = ["strm", "file"]
    # brkp = ["^deflate", "^inflate", "^gz", "^compress", "^uncompress"]

    # Parameters for libssl
    # targetStructs = ["s", "ssl", "ss", "libctx", "ctx"]
    # argv = "certs/ recipes/90-test_sslapi_data/passwd.txt temp_api_test default default.cnf recipes/90-test_sslapi_data/dhparams.pem"
    # brkp = ["^SSL_", "^ssl_"]

    gdbSetup(brkp, argv)

    while(True):
        funcName = gdb.selected_frame().function()
        userCall = UserCall(funcName, targetStructs)
        userCall.doCorruption(-1)
        finishFuncHandler(funcName)

        # Continue to next breakpoint
        finishCurrentFunc()
        gdb.execute("continue")


# Main logic starts here
main()