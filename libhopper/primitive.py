from dataclasses import dataclass


@dataclass
class Primitive:
    action: str
    constraints: list
    addr_range: tuple
    poc_vector: bytes

    def __init__(self, action, constraints, addr_range, poc_vector):
        self.action = action
        self.constraints = constraints
        self.addr_range = addr_range
        self.poc_vector = poc_vector
    
    def __repr__(self):
        return f"<{self.__class__.__name__} {self.action} {[hex(r) for r in self.addr_range]}>"