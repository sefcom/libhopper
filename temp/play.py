import angr
import claripy

proj = angr.Project("./tests/libdummy/libdummy.so")

state_opts = set()
# added_options.add(angr.options.AUTO_REFS)
state_opts.add(angr.options.TRACK_MEMORY_ACTIONS)
state_opts.add(angr.options.TRACK_JMP_ACTIONS)

# Inputs
func_addr = proj.loader.find_symbol("libapi_exec").rebased_addr
struct_addr = 0xdeadbeef
struct_size = 0x78

begin_state:angr.sim_state.SimState
begin_state = proj.factory.call_state(func_addr, add_options=state_opts)
begin_state.registers.store("rbp", 0)

# Overwrite internal state struct with symbolic value
symbolic_struct = claripy.BVS("sym_struct", struct_size * 8)
begin_state.memory.store(struct_addr, symbolic_struct)
begin_state.registers.store("rdi", struct_addr)

simgr = proj.factory.simgr(begin_state)
try:
    simgr.run()
except:
    print("Simulation manager errored!")
    print(simgr.errored)

# Examine history events
end_state:angr.sim_state.SimState
# end_state = simgr.deadended[0]
end_state = simgr.unconstrained[0]
solver = begin_state.solver

# Carry out the information step by step
histories = end_state.history.lineage
for h in histories:
    # solver = claripy.Solver()
    h: angr.state_plugins.SimStateHistory
    tainted_events = [e for e in h.recent_events if isinstance(e, angr.state_plugins.SimActionData) and e.is_symbolic]
    tainted_jump = h.jump_target if h.jump_target != None and h.jump_target.symbolic else None
    solver.add([c.ast for c in h.recent_constraints])
    solver.simplify()

    if tainted_events:
        print(tainted_events)
        for e in tainted_events:
            range_min = solver.min(e.addr.ast)
            range_max = solver.max(e.addr.ast)
            if range_min == range_max:
                continue

    if tainted_jump != None:
        print(tainted_jump)
        pass