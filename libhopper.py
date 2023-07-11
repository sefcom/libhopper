import angr
import claripy


if __name__ == "__main__":
    proj_opts = {"main_opts": {"backend": "elfcore"}}
    proj = angr.Project("./libapi_write", load_options=proj_opts)

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
    # TODO: replace struct addr & size
    concrete_ctx = state.memory.load(state.regs.rdi.v, 0x68)
    # TODO: replace struct size
    symbolic_ctx = claripy.Concat(*[state.solver.BVS(f"sym_struct_{b}", 8) for b in range(0x68)])
    state.solver.add(concrete_ctx == symbolic_ctx)
    # TODO: replace struct addr
    state.memory.store(state.regs.rdi.v, symbolic_ctx)

    simgr = proj.factory.simgr(state)
    # TODO: replace func finish addr
    simgr.run(until=lambda sm: sm.active[0].addr == 0x55555555525c)

    # Examine history
    new_state:angr.sim_state.SimState
    new_state = simgr.active[0]
    read_events = new_state.history.filter_actions(read_from="mem")
    write_events = new_state.history.filter_actions(write_to="mem")

    tainted_jumps = [jump_target for jump_target in new_state.history.jump_targets if jump_target.symbolic]
    tainted_reads = [event for event in read_events if event.is_symbolic]
    tainted_writes = [event for event in write_events if event.is_symbolic]

    for i in tainted_jumps:
        print(f"PC: {hex(i.ins_addr)} - JUMP: {i.addr}")
    for i in tainted_reads:
        print(f"PC: {hex(i.ins_addr)} - READ: {i.addr}")
    for i in tainted_writes:
        print(f"PC: {hex(i.ins_addr)} - WRITE: {i.addr}")
    
    input()
