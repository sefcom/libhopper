import gdb
from libhopper.parse_config import parse_config
import os


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


def parse_args(struct_type):
    args = str(gdb.execute("info args", to_string=True))
    if "No arguments" in args:
        return None

    args = args.strip().split("\n")
    for arg in args:
        temp = arg.split(" ")
        arg_name = temp[0]
        try:
            struct = gdb.parse_and_eval(arg_name).dereference()
        except:
            continue
        if struct.type.name == struct_type:
            return int(struct.address)
    
    return None


def main(gen_core_config_file, analysis_config_file):
    gen_core_config = parse_config(gen_core_config_file)
    core_dump_dir = gen_core_config["core_dump_dir"]
    struct_type = gen_core_config["struct_type"]
    brkp_regex = gen_core_config["brkp_regex"]
    test_argv = gen_core_config["test_argv"]

    # Check core dump directory
    gdb.execute(f"shell mkdir -p {core_dump_dir}")

    # Install breakpoints
    gdb.execute(f"start {test_argv}")
    for regex in brkp_regex:
        gdb.rbreak(regex)

    # Write analysis configuration file
    with open(analysis_config_file, "w") as f:
        f.write("# Auto-generated analysis configuration file\n")

    # Resume execution
    gdb.execute("continue")

    # Look up struct size
    struct_size = gdb.lookup_type(struct_type).sizeof

    while True:
        try:
            frame = gdb.selected_frame()
        except:
            break

        func_name = frame.function().name
        gdb.execute(f"clear {func_name}")

        struct_addr = parse_args(struct_type)
        if struct_addr == None:
            gdb.execute("continue")
            continue

        ret_addr = frame.older().pc()
        core_file = f"{core_dump_dir}{func_name}.dump"
        gdb.execute(f"generate-core-file {core_file}")

        # Write analysis config file
        with open(analysis_config_file, "a") as f:
            f.write("---\n")
            f.write(f"core_file: {core_file}\n")
            f.write(f"struct_addr: {hex(struct_addr)}\n")
            f.write(f"struct_size: {hex(struct_size)}\n")
            f.write(f"ret_addr: {hex(ret_addr)}\n")

        gdb.execute("continue")


# Only run in gdb, not anywhere else
if __name__ == "__main__":
    env = os.environ
    gen_core_config = env["GEN_CORE_CONFIG"]
    analysis_config = env["ANALYSIS_CONFIG"]
    main(gen_core_config, analysis_config)
