import angr
import claripy
import cle
from itertools import chain
from .parse_config import parse_all
from .primitive import Primitive


def tainted_ast_to_primitive(
    ast: claripy.ast.BV, mem_range: chain[int], solver: claripy.Solver, action: str
) -> Primitive:

    # Extract possiable base
    base = 0
    for c in ast.children_asts():
        if c.concrete and c.concrete_value in mem_range:
            base = c.concrete_value
            break

    addr_range = (solver.min(ast) - base, solver.max(ast) - base)
    poc_vector = solver.eval(ast, 1)[0]

    if base != 0:
        primitive = Primitive(
            f"rela-{action}", solver.constraints, (base, addr_range), ast, poc_vector
        )
    else:
        primitive = Primitive(
            f"arbi-{action}", solver.constraints, (addr_range), ast, poc_vector
        )

    return primitive


def analyze_history(project: angr.Project, end_state: angr.SimState) -> list[Primitive]:
    primitives: list[Primitive] = []
    solver = claripy.Solver()
    mem_range = chain.from_iterable(
        (
            range(obj.min_addr, obj.max_addr + 1)
            for obj in project.loader.all_elf_objects
        )
    )

    # Carry out the information step by step
    for h in end_state.history.lineage:
        h: angr.state_plugins.SimStateHistory
        solver.add([c.ast for c in h.recent_constraints])
        solver.simplify()

        tainted_events = [
            e
            for e in h.recent_actions
            if isinstance(e, angr.state_plugins.SimActionData) and e.addr.symbolic
        ]

        tainted_jump = (
            h.jump_target if h.jump_target != None and h.jump_target.symbolic else None
        )

        # Extract primitives
        for e in tainted_events:
            primitives.append(
                tainted_ast_to_primitive(e.addr.ast, mem_range, solver, e.action)
            )

        if tainted_jump != None:
            primitives.append(
                tainted_ast_to_primitive(tainted_jump, mem_range, solver, "exec")
            )

    print(primitives)
    return primitives


def analysis(analysis_config_file: str, index: int) -> list[Primitive]:
    print(f"Analysis {index}")

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
    begin_state: angr.SimState = project.factory.blank_state(add_options=state_opts)

    # Config blank state
    core_obj: cle.ELFCore = project.loader.elfcore_object
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
    simgr: angr.SimulationManager = project.factory.simgr(begin_state)
    simgr.run(until=lambda sm: sm.active[0].addr == ret_addr)

    # Examine history events
    end_state: angr.SimState = simgr.active[0]

    return analyze_history(project, end_state)
