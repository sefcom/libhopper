import angr
import claripy


def finish_func(simgr:angr.sim_manager.SimulationManager):
    state = simgr.active[0]
    # TODO: replace address
    # return state.regs.rip.v == 0x555555555246 # libapi_read
    return state.regs.rip.v == 0x55555555525c

if __name__ == "__main__":
    proj = angr.Project("./libapi_write", main_opts={"backend": "elfcore"})

    added_options = set()
    # added_options.add(angr.options.AUTO_REFS)
    added_options.add(angr.options.TRACK_MEMORY_ACTIONS)
    added_options.add(angr.options.TRACK_JMP_ACTIONS)
    
    state:angr.sim_state.SimState
    state = proj.factory.blank_state(add_options=added_options)

    # Config symbolic state
    core_obj = proj.loader.elfcore_object
    assert(core_obj != None)
    for regval in core_obj.initial_register_values():
        try:
            setattr(state.regs, regval[0], regval[1])
        except:
            pass

    # Overwrite internal state struct with symbolic value
    # TODO: replace addr & length
    concrete_ctx = state.memory.load(state.regs.rdi.v, 0x68)
    # TODO: replace length
    symbolic_ctx = claripy.Concat(*[state.solver.BVS(f"sym_struct_{b}", 8) for b in range(0x68)])
    state.solver.add(concrete_ctx == symbolic_ctx)
    # TODO: replace addr
    state.memory.store(state.regs.rdi.v, symbolic_ctx)

    simgr = proj.factory.simgr(state)
    simgr.run(until=finish_func)

    # Examine history
    new_state:angr.sim_state.SimState
    new_state = simgr.active[0]
    read_events = new_state.history.filter_actions(read_from="mem")
    write_events = new_state.history.filter_actions(write_to="mem")

    tainted_jumps = [jump_target for jump_target in new_state.history.jump_targets if jump_target.symbolic]
    tainted_reads = [event for event in read_events if event.is_symbolic]
    tainted_writes = [event for event in write_events if event.is_symbolic]

    for i in tainted_reads:
        print(f"PC: {hex(i.ins_addr)} - READ: {i.addr}")
    for i in tainted_writes:
        print(f"PC: {hex(i.ins_addr)} - WRITE: {i.addr}")
    
    input()
