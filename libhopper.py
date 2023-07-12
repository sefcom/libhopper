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
    
    state:angr.sim_state.SimState
    state = proj.factory.blank_state(add_options=state_opts)

    # Config symbolic state
    core_obj = proj.loader.elfcore_object
    assert(core_obj != None)
    for regval in core_obj.initial_register_values():
        try:
            state.registers.store(regval[0], regval[1])
        except:
            pass

    # Overwrite internal state struct with symbolic value
    concrete_ctx = state.memory.load(struct_addr, struct_size)
    symbolic_ctx = claripy.Concat(*[state.solver.BVS(f"sym_struct_{b}", 8) for b in range(struct_size)])
    state.solver.add(concrete_ctx == symbolic_ctx)
    state.memory.store(struct_addr, symbolic_ctx)

    simgr = proj.factory.simgr(state)
    try:
        simgr.run(until=lambda sm: sm.active[0].addr == upper_frame)
    except:
        print("Simulation manager errored!")
        import IPython; IPython.embed()

    # Examine history
    new_state:angr.sim_state.SimState
    new_state = simgr.active[0]
    # read_events = new_state.history.filter_actions(read_from="mem")
    # write_events = new_state.history.filter_actions(write_to="mem")

    # tainted_jumps = [jump_target for jump_target in new_state.history.jump_targets if jump_target.symbolic]
    # tainted_reads = [event for event in read_events if event.is_symbolic]
    # tainted_writes = [event for event in write_events if event.is_symbolic]

    # for i in tainted_jumps:
    #     print(f"PC: {hex(i.ins_addr)} - JUMP: {i.addr}")
    # for i in tainted_reads:
    #     print(f"PC: {hex(i.ins_addr)} - READ: {i.addr}")
    # for i in tainted_writes:
    #     print(f"PC: {hex(i.ins_addr)} - WRITE: {i.addr}")

    histories = list(new_state.history.lineage)[1:]
    solver = claripy.Solver()
    
    for h in histories:
        # TODO
        sym_reads = [e.addr for e in h.recent_events if isinstance(e, angr.state_plugins.sim_action.sim_action.SimActionData) and e.is_symbolic]

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

    target_structs = []
    brkp_regex = []
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
            analysis(core_dump, struct_addr, struct_size, upper_frame)

        gdb.execute(f"clear {func_name}")
        gdb.execute("c")
