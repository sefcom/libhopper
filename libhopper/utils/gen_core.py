import gdb
from .parse_config import parse_config

def config_gdb():
    gdb_setup = (
        "set confirm off",
        "set verbose off",
        "set pagination off",
        "set print elements 0",
        "set history save on",
        "set output-radix 0x10",
        "set print pretty on",
        "set disassembly-flavor intel",
    )
    for cmd in gdb_setup:
        try:
            gdb.execute(cmd)
        except gdb.error:
            pass

def parse_args(target_structs):
    struct_addr = None
    struct_size = None

    args = str(gdb.execute("info args", to_string=True))
    if "No arguments" in args:
        return struct_addr, struct_size

    args = args.strip().split("\n")
    for arg in args:
        temp = arg.split(" ")
        arg_name = temp[0]
        if arg_name in target_structs:
            struct = gdb.parse_and_eval(arg_name).dereference()
            struct_addr = int(struct.address)
            struct_size = struct.type.sizeof
    
    return struct_addr, struct_size

def main(config_file):
    config = parse_config(config_file)
    struct_names = config["struct_names"]
    brkp_regex = config["brkp_regex"]
    prog_argv = config["prog_argv"]

    gdb.execute(f"start {prog_argv}")
    for regex in brkp_regex:
        gdb.rbreak(regex)
    gdb.execute("continue")

    while True:
        try:
            frame = gdb.selected_frame()
        except:
            break

        func_name = frame.function().name
        struct_addr, struct_size = parse_args(struct_names)
        upper_frame = frame.older().pc()
        if struct_addr != None and struct_size != None:
            gdb.execute(f"generate-core-file {func_name}.dump")

        gdb.execute(f"clear {func_name}")
        gdb.execute("continue")

if __name__ == "__main__":
    main("analysis.yaml")