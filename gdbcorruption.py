import gdb
import struct

def p8(x):
    return struct.pack("<B", x)

def p16(x):
    return struct.pack("<H", x)

def p32(x):
    return struct.pack("<I", x)

def p64(x):
    return struct.pack("<Q", x)

def u8(x):
    return struct.unpack("<B", x)[0]

def u16(x):
    return struct.unpack("<H", x)[0]

def u32(x):
    return struct.unpack("<I", x)[0]

def u64(x):
    return struct.unpack("<Q", x)[0]

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
    
    def checkAccess(self):
        try:
            gdb.execute(f"p *{self.name}")
            return True
        except gdb.error:
            return False

    def bitFlip(self, data):
        bitflip = b""
        for byte in data:
            bitflip += p8(~byte & 0xff)
        return bitflip
    
    def getVal(self, len, off):
        # Directly modify / corrupt the struct
        inferior = gdb.inferiors()[0]
        try:
            return inferior.read_memory(int(self.val, 16) + off, len).tobytes()
        except gdb.error:
            # Unaccessible
            return

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
    
    def doFullCorrupt(self, arg, flip):
        corruptAttempt()

        data = "A" * arg.size
        if flip:
            data = arg.bitFlip(arg.getVal(arg.size, 0))
        
        arg.setVal(data, 0)

        finishCurrentFunc()

        if checkCrash():
            crashFuncHandler(self.name, arg.name, "Full Corrupt", flip, 0, arg.size)
            return

        corruptRestore()
    
    def doOverflow(self, arg, bound, flip):
        for i in range(0, bound, 1):
            corruptAttempt()

            data = "A" * i
            if flip:
                data = arg.bitFlip(arg.getVal(i, 0))

            arg.setVal(data, 0)

            finishCurrentFunc()

            if checkCrash():
                crashFuncHandler(self.name, arg.name, "Overflow", flip, 0, i)
                break
        
            corruptRestore()

    def doArbiWrite(self, arg, len, flip):
        for i in range(0, arg.size, 1):
            corruptAttempt()

            data = "A" * len
            if flip:
                data = arg.bitFlip(arg.getVal(len, i))
            arg.setVal(data, i)

            finishCurrentFunc()

            # Examine if crash happens
            if checkCrash():
                crashFuncHandler(self.name, arg.name, "Arbitrary Write", flip, i, i + len)
                continue
        
            corruptRestore()

    def doCorruption(self, step):
        # Search valid arg
        for arg in self.args:
            if arg.name not in self.targetStructs:
                continue
            if arg.val == "0x0":
                continue
            if not arg.checkAccess():
                continue

            self.doFullCorrupt(arg, False)
            self.doFullCorrupt(arg, True)
            # self.doOverflow(arg, arg.size, False)
            # self.doOverflow(arg, arg.size, True)
            # self.doArbiWrite(arg, arg.size, False)
            # self.doArbiWrite(arg, arg.size, True)
    

funcs = []

def stopHandler(event):
    if hasattr (event, 'stop_signal'):
        gdb.execute("continue")

def gdbSetup(brkpRegx, argv):
    global funcs
    
    gdb.execute("set confirm off")
    gdb.execute("set pagination off")
    gdb.execute(f"start {argv}")

    for regx in brkpRegx:
        gdb.rbreak(f"{regx}")

    with open("Todo_Funcs.txt", "r") as f:
        todo = f.read().strip().split("\n")
    
    # Record finished funcs
    with open("Finish_Funcs.txt", "r") as f:
        finish = f.read().strip().split("\n")
    
    funcs = list(set(todo) - set(finish))
    
    gdb.events.stop.connect(stopHandler)
    gdb.execute("continue")


def corruptAttempt():
    # Attempt to corrupt data
    gdb.execute("checkpoint")
    gdb.execute("restart 1")

def corruptRestore():
    # Restore normal execution routine
    gdb.execute("restart 0")
    gdb.execute("delete checkpoint 1")

def checkCrash():
    msg = gdb.execute("info checkpoints", to_string=True)
    assert(msg != None)
    return "No checkpoints" in msg.strip()

def finishCurrentFunc():
    gdb.execute("disable")
    gdb.execute("finish")
    gdb.execute("enable")

def crashFuncHandler(funcName, argName, corruptType, flipBit, off_start, off_end):
    with open("Crash_Funcs.txt", "a") as f:
        f.write(f"{funcName} - {argName} - {corruptType} - {flipBit} - {off_start} - {off_end}\n")
    
def finishFuncHandler(funcName):
    with open("Finish_Funcs.txt", "a") as f:
        f.write(f"{funcName}\n")

# Main logic 
def main():
    # TODO: Config this before start!
    # Parameters for unit test
    targetStructs = ["state"]
    brkpRegx = ["^libapi_"]
    argv = ""

    # Parameters for libpng
    # targetStructs = ["png_ptr", "info_ptr"]
    # brkpRegx = ["^png_"]
    # argv = ""

    # Parameters for libjpeg
    # targetStructs = ["cinfo"]
    # brkpRegx = ["^jpeg_"]
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
    # brkpRegx = ["^xml", "^html"]

    # Parameters for zlib
    # targetStructs = ["strm", "file"]
    # brkpRegx = ["^deflate", "^inflate", "^gz", "^compress", "^uncompress"]

    # Parameters for libssl
    # targetStructs = ["s", "ssl", "ss", "libctx", "ctx"]
    # argv = "certs/ recipes/90-test_sslapi_data/passwd.txt temp_api_test default default.cnf recipes/90-test_sslapi_data/dhparams.pem"
    # brkpRegx = ["^SSL_", "^ssl_"]

    gdbSetup(brkpRegx, argv)

    while(True):
        try:
            funcName = gdb.selected_frame().function()
            if funcName.name in funcs:
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