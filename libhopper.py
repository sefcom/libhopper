import angr
import claripy


def finish_func(simgr:angr.sim_manager.SimulationManager):
    state = simgr.active[0]
    # TODO: replace address
    return state.regs.rip.v == 0x555555555246

if __name__ == "__main__":
    proj = angr.Project("./libapi_read", main_opts={"backend": "elfcore"})
    state:angr.sim_state.SimState
    state = proj.factory.blank_state()

    # Config symbolic state
    core_obj = proj.loader.elfcore_object
    assert(core_obj != None)
    for regval in core_obj.initial_register_values():
        print(regval[0], hex(regval[1]))
        try:
            setattr(state.regs, regval[0], regval[1])
        except:
            pass

    # Overwrite internal struct with symbolic value
    # TODO: replace length
    concrete_ctx = state.memory.load(state.regs.rdi.v, 0x68)
    # TODO: replace length
    # symbolic_ctx = state.solver.BVS("symbolic_ctx", 0x68 * 8)
    symbolic_ctx = claripy.Concat(*[state.solver.BVS(f"byte_{b}", 8) for b in range(0x68)])
    state.solver.add(concrete_ctx == symbolic_ctx)
    state.memory.store(state.regs.rdi.v, symbolic_ctx)

    simgr = proj.factory.simgr(state)
    simgr.run(until=finish_func)

    # Examine history
    new_state:angr.sim_state.SimState
    new_state = simgr.active[0]
    events = new_state.history.events
    tainted_jumps = [jump_target for jump_target in new_state.history.jump_targets if jump_target.symbolic]
    # tainted_reads = [event for event in events if isinstance(event, angr.state_plugins.sim_action.SimAction) and event.is_symbolic and event.action == "read"]
    # tainted_writes = [event for event in events if event.is_symbolic and event.action == "write"]

    # tainted_writes[0].addr
    # tainted_writes[0].addr.variables
    
    input()
