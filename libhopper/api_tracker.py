import claripy
from angr import Project, SimState, SimStatePlugin, SIM_PROCEDURES
from .primitive import Primitive


def reg_api_tracker_hooks(project: Project, begin_state: SimState):
    # Posix C library function hooks (only for those that can produce API primitives)
    project.hook_symbol("open", openHook())
    project.hook_symbol("read", readHook())
    project.hook_symbol("write", writeHook())

    # SIM_PROCEDURES["posix"]["open"] = openHook
    # SIM_PROCEDURES["posix"]["read"] = readHook
    # SIM_PROCEDURES["posix"]["write"] = writeHook

    # Standard C library function hooks (only for those that can produce API primitives)
    project.hook_symbol("fopen", fopenHook())
    project.hook_symbol("fread", freadHook())
    project.hook_symbol("fwrite", fwriteHook())
    project.hook_symbol("fgets", fgetsHook())
    project.hook_symbol("fputs", fputsHook())
    project.hook_symbol("memcpy", memcpyHook())
    project.hook_symbol("strcpy", strcpyHook())
    project.hook_symbol("strncpy", strncpyHook())
    project.hook_symbol("free", freeHook())

    # SIM_PROCEDURES["libc"]["fopen"] = fopenHook
    # SIM_PROCEDURES["libc"]["fread"] = freadHook
    # SIM_PROCEDURES["libc"]["fwrite"] = fwriteHook
    # SIM_PROCEDURES["libc"]["fgets"] = fgetsHook
    # SIM_PROCEDURES["libc"]["fputs"] = fputsHook
    # SIM_PROCEDURES["libc"]["memcpy"] = memcpyHook
    # SIM_PROCEDURES["libc"]["strcpy"] = strcpyHook
    # SIM_PROCEDURES["libc"]["strncpy"] = strncpyHook
    # SIM_PROCEDURES["libc"]["free"] = freeHook

    # Register the APITracker plugin
    begin_state.register_plugin("api_tracker", APITracker())


def tainted_addr_to_primitive(
    addr: claripy.ast.BV, solver: claripy.Solver, action: str
) -> Primitive:
    addr_range = (solver.min(addr), solver.max(addr))
    poc_vector = solver.eval(addr)
    return Primitive(action, solver.constraints, addr_range, addr, poc_vector)


class APITracker(SimStatePlugin):
    api_primitives: list[Primitive]

    def __init__(self, api_primitives=None):
        super().__init__()
        self.api_primitives = list() if api_primitives is None else api_primitives

    @SimStatePlugin.memo
    def copy(self, memo):
        return APITracker(api_primitives=self.api_primitives.copy())

    def merge(self, others, merge_conditions, common_ancestor=None):
        # Just merge all the primitives
        for o in others:
            self.api_primitives.extend(o.api_primitives)


# Assuming the project already registered the APITracker plugin as api_tracker

# Posix C library function hooks (only for those that can produce API primitives)


class openHook(SIM_PROCEDURES["posix"]["open"]):
    def run(self, p_addr, flags, mode):
        if self.state.solver.symbolic(p_addr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(p_addr, self.state.solver, "file-open")
            )

        return super().run(p_addr, flags, mode)


class readHook(SIM_PROCEDURES["posix"]["read"]):
    def run(self, fd, dst, length):
        if self.state.solver.symbolic(dst):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(dst, self.state.solver, "file-read")
            )

        return super().run(fd, dst, length)


class writeHook(SIM_PROCEDURES["posix"]["write"]):
    def run(self, fd, src, length):
        if self.state.solver.symbolic(src):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(src, self.state.solver, "file-write")
            )

        return super().run(fd, src, length)


# Standard C library function hooks (only for those that can produce API primitives)


class fopenHook(SIM_PROCEDURES["libc"]["fopen"]):
    def run(self, p_addr, m_addr):
        if self.state.solver.symbolic(p_addr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(p_addr, self.state.solver, "file-open")
            )

        return super().run(p_addr, m_addr)


class freadHook(SIM_PROCEDURES["libc"]["fread"]):
    def run(self, dst, size, nm, file_ptr):
        if self.state.solver.symbolic(dst):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(dst, self.state.solver, "file-read")
            )

        return super().run(dst, size, nm, file_ptr)


class fwriteHook(SIM_PROCEDURES["libc"]["fwrite"]):
    def run(self, src, size, nmemb, file_ptr):
        if self.state.solver.symbolic(src):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(src, self.state.solver, "file-write")
            )

        return super().run(src, size, nmemb, file_ptr)


class fgetsHook(SIM_PROCEDURES["libc"]["fgets"]):
    def run(self, dst, size, file_ptr):
        if self.state.solver.symbolic(dst):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(dst, self.state.solver, "file-read")
            )

        return super().run(dst, size, file_ptr)


class fputsHook(SIM_PROCEDURES["libc"]["fputs"]):
    def run(self, str_addr, file_ptr):
        if self.state.solver.symbolic(str_addr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(str_addr, self.state.solver, "file-write")
            )

        return super().run(str_addr, file_ptr)


class memcpyHook(SIM_PROCEDURES["libc"]["memcpy"]):
    def run(self, dst_addr, src_addr, limit):
        if self.state.solver.symbolic(dst_addr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(dst_addr, self.state.solver, "mem-write")
            )

        if self.state.solver.symbolic(src_addr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(src_addr, self.state.solver, "mem-read")
            )

        return super().run(dst_addr, src_addr, limit)


class strcpyHook(SIM_PROCEDURES["libc"]["strcpy"]):
    def run(self, dst, src):
        if self.state.solver.symbolic(dst):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(dst, self.state.solver, "mem-write")
            )

        if self.state.solver.symbolic(src):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(src, self.state.solver, "mem-read")
            )

        return super().run(dst, src)


class strncpyHook(SIM_PROCEDURES["libc"]["strncpy"]):
    def run(self, dst_addr, src_addr, limit, src_len=None):
        if self.state.solver.symbolic(dst_addr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(dst_addr, self.state.solver, "mem-write")
            )

        if self.state.solver.symbolic(src_addr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(src_addr, self.state.solver, "mem-read")
            )

        return super().run(dst_addr, src_addr, limit, src_len)


class freeHook(SIM_PROCEDURES["libc"]["free"]):
    def run(self, ptr):
        if self.state.solver.symbolic(ptr):
            self.state.api_tracker.api_primitives.append(
                tainted_addr_to_primitive(ptr, self.state.solver, "heap-free")
            )

        return super().run(ptr)
