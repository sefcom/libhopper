from dataclasses import dataclass


@dataclass
class Primitive:
    action: str
    constraints: list
    addr_range: tuple
    poc_vector: bytes

    def __init__(self, action, constraints, addr_range, bit_vector, poc_vector):
        self.action = action
        self.constraints = constraints
        self.addr_range = addr_range
        self.bit_vector = bit_vector
        self.poc_vector = poc_vector

    def __repr__(self):
        def recur_hex(value):
            if isinstance(value, tuple):
                return tuple(recur_hex(item) for item in value)
            else:
                return hex(value)

        return f"<{self.__class__.__name__} {self.action} {recur_hex(self.addr_range)}>"
