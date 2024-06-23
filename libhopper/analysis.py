import angr
import claripy
import cle
from .parse_config import parse_all
from .primitive import Primitive


def analysis(analysis_config_file: str, index: int) -> list[Primitive]:
    # Parse configuration
    analysis_config = parse_all(analysis_config_file)
    core_file = analysis_config[index]["core_file"]
    struct_addr = analysis_config[index]["struct_addr"]
    struct_size = analysis_config[index]["struct_size"]
    ret_addr = analysis_config[index]["ret_addr"]

    # Load the core dump
    proj_ops = {"backend": "elfcore"}
    project = angr.Project(core_file, main_opts=proj_ops)

    # Prepare state options
    state_opts = set()
    state_opts.add(angr.options.TRACK_MEMORY_ACTIONS)
    state_opts.add(angr.options.TRACK_JMP_ACTIONS)

    # Prepare initial state
    begin_state: angr.sim_state.SimState = project.factory.blank_state(
        add_options=state_opts
    )

    # Config blank state
    core_obj: cle.backends.ELFCore = project.loader.elfcore_object
    for regval in core_obj.thread_registers().items():
        try:
            begin_state.registers.store(regval[0], regval[1])
        except:
            pass

    # Overwrite internal state struct with symbolic value
    concrete_struct: claripy.ast.BV = begin_state.memory.load(struct_addr, struct_size)
    symbolic_struct: claripy.ast.BV = claripy.BVS("sym_struct", struct_size * 8)
    begin_state.solver.add(concrete_struct == symbolic_struct)
    begin_state.memory.store(struct_addr, symbolic_struct)

    # Run simulation manager
    simgr: angr.sim_manager.SimulationManager = project.factory.simgr(begin_state)
    simgr.run(until=lambda sm: sm.active[0].addr == ret_addr)

    # Examine history events
    end_state: angr.sim_state.SimState = simgr.active[0]

    # Carry out the information step by step
    primitives: list[Primitive] = []
    solver = claripy.Solver()
    for h in end_state.history.lineage:
        h: angr.state_plugins.SimStateHistory
        solver.add([c.ast for c in h.recent_constraints])
        solver.simplify()

        tainted_events = [
            e
            for e in h.recent_actions
            if isinstance(e, angr.state_plugins.SimActionData) and e.is_symbolic
        ]
        tainted_jump = (
            h.jump_target if h.jump_target != None and h.jump_target.symbolic else None
        )

        # Extract primitives
        for e in tainted_events:
            # TODO: More detailed analysis on this
            addr_range = (solver.min(e.addr.ast), solver.max(e.addr.ast))
            if addr_range[0] == addr_range[1]:
                continue
            poc_vector: bytes = bytes.fromhex(
                hex(solver.eval(symbolic_struct, 1)[0])[2:]
            )
            primitive = Primitive(e.action, solver.constraints, addr_range, poc_vector)
            primitives.append(primitive)

        if tainted_jump != None:
            addr_range = (solver.min(tainted_jump), solver.max(tainted_jump))
            poc_vector: bytes = bytes.fromhex(
                hex(solver.eval(symbolic_struct, 1)[0])[2:]
            )
            primitive = Primitive("exec", solver.constraints, addr_range, poc_vector)
            primitives.append(primitive)

    print(primitives)
    return primitives
