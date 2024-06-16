import angr
import claripy
import cle
from typing import Any


class Analyzer:
    project: angr.Project
    state_opts: set

    def __init__(
        self,
        func_dump_path: str,
        proj_ops: dict[str, Any] | None = None,
        state_opts: set | None = None,
    ) -> None:
        if proj_ops is None:
            proj_ops = {"backend": "elfcore"}
        self.project = angr.Project(func_dump_path, main_opts=proj_ops)

        if state_opts is None:
            state_opts = set()
            state_opts.add(angr.options.TRACK_MEMORY_ACTIONS)
            state_opts.add(angr.options.TRACK_JMP_ACTIONS)
        self.state_opts = state_opts

    def analyze(self, struct_addr: int, struct_size: int, ret_addr: int) -> None:
        begin_state: angr.sim_state.SimState = self.project.factory.blank_state(
            add_options=self.state_opts
        )

        # Config blank state
        core_obj: cle.backends.ELFCore = self.project.loader.elfcore_object
        for regval in core_obj.initial_register_values():
            try:
                begin_state.registers.store(regval[0], regval[1])
            except:
                pass

        # Overwrite internal state struct with symbolic value
        concrete_struct: claripy.ast.bv.BV = begin_state.memory.load(
            struct_addr, struct_size
        )
        symbolic_struct: claripy.ast.bv.BV = claripy.BVS("sym_struct", struct_size * 8)
        begin_state.solver.add(concrete_struct == symbolic_struct)
        begin_state.memory.store(struct_addr, symbolic_struct)

        # Run simulation manager
        simgr: angr.sim_manager.SimulationManager = self.project.factory.simgr(
            begin_state
        )
        simgr.run(until=lambda sm: sm.active[0].addr == ret_addr)

        # Examine history events
        end_state: angr.sim_state.SimState = simgr.active[0]
        solver: claripy.solvers.Solver = claripy.Solver()

        # Carry out the information step by step
        for h in end_state.history.lineage:
            h: angr.state_plugins.SimStateHistory
            tainted_events = [
                e
                for e in h.recent_events
                if isinstance(e, angr.state_plugins.SimActionData) and e.is_symbolic
            ]
            tainted_jump = (
                h.jump_target
                if h.jump_target != None and h.jump_target.symbolic
                else None
            )
            solver.add([c.ast for c in h.recent_constraints])
            solver.simplify()

            if tainted_events:
                print(tainted_events)
                pass

            if tainted_jump:
                print(tainted_jump)
                pass
