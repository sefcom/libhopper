# import gdb
import angr
import claripy


def analysis(core_dump, struct_addr, struct_size, upper_frame):
    proj_opts = {"main_opts": {"backend": "elfcore"}}
    proj = angr.Project(core_dump, load_options=proj_opts)

    state_opts = set()
    # added_options.add(angr.options.AUTO_REFS)
    state_opts.add(angr.options.TRACK_MEMORY_ACTIONS)
    state_opts.add(angr.options.TRACK_JMP_ACTIONS)
    
    begin_state:angr.sim_state.SimState
    begin_state = proj.factory.blank_state(add_options=state_opts)

    # Config symbolic state
    core_obj = proj.loader.elfcore_object
    assert(core_obj != None)
    for regval in core_obj.initial_register_values():
        try:
            begin_state.registers.store(regval[0], regval[1])
        except:
            pass

    # Overwrite internal state struct with symbolic value
    concrete_ctx = begin_state.memory.load(struct_addr, struct_size)
    # symbolic_ctx = claripy.Concat(*[begin_state.solver.BVS(f"sym_struct_{b}", 8) for b in range(struct_size)])
    symbolic_ctx = claripy.BVS("sym_struct", struct_size * 8)
    begin_state.solver.add(concrete_ctx == symbolic_ctx)
    begin_state.memory.store(struct_addr, symbolic_ctx)

    simgr = proj.factory.simgr(begin_state)
    try:
        simgr.run(until=lambda sm: sm.active[0].addr == upper_frame)
    except:
        print("Simulation manager errored!")
        import IPython; IPython.embed()

    # Examine history
    end_state:angr.sim_state.SimState
    end_state = simgr.active[0]
    read_events = end_state.history.filter_actions(read_from="mem")
    write_events = end_state.history.filter_actions(write_to="mem")

    tainted_reads = [event for event in read_events[::-1] if event.is_symbolic]
    tainted_writes = [event for event in write_events[::-1] if event.is_symbolic]
    tainted_jumps = [jump_target for jump_target in end_state.history.jump_targets if jump_target.symbolic]
    constraints = [constraint.ast for constraint in end_state.history.constraints_since(begin_state)]

    solver = claripy.Solver()
    solver.add(constraints)
    read_ranges = [(solver.min(e.addr.ast), solver.max(e.addr.ast)) for e in tainted_reads]
    write_ranges = [(solver.min(e.addr.ast), solver.max(e.addr.ast)) for e in tainted_writes]
    jump_ranges = [(solver.min(e), solver.max(e)) for e in tainted_jumps]

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


if __name__ == "__main__":
    # Config gdb before start
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

    target_structs = ["state"]
    brkp_regex = ["^libapi_"]
    argv = ""
    # Parameters for libpng
    # target_structs = ["png_ptr", "info_ptr"]
    # brkp_regex = ["^png_"]
    # argv = ""
    # Parameters for zlib
    # target_structs = ["strm", "file"]
    # brkp_regex = ["^deflate", "^inflate", "^gz", "^compress", "^uncompress"]
    # argv = ""

    gdb.execute(f"start {argv}")
    for regex in brkp_regex:
        gdb.rbreak(regex)
    gdb.execute("c")
    
    while True:
        frame = gdb.selected_frame()

        func_name = frame.function().name
        core_dump = f"{func_name}.dump"

        struct_addr, struct_size = parse_args(target_structs)

        upper_frame = frame.older().pc()
        
        if struct_addr != None:
            gdb.execute(f"gcore {core_dump}")
            # analysis(core_dump, struct_addr, struct_size, upper_frame)

        gdb.execute(f"clear {func_name}")
        gdb.execute("c")
