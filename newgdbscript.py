import gdb
import subprocess
import sys
import os
import yaml


class LibFunctionCall(gdb.Breakpoint):
    def get_args(self):
        pass

    def stop(self) -> bool:
        print(gdb.selected_frame().function().name)
        return False
        

if __name__ == "__main__":
    gdb_init_settings = (
        "set confirm off",
        "set verbose off",
        "set pagination off",
        "set print pretty on",
        "set disassembly-flavor intel"
    )

    for cmd in gdb_init_settings:
        try:
            gdb.execute(cmd)
        except:
            pass
    
    gdb.execute("start")
    LibFunctionCall("libapi_init")
    gdb.execute("continue")

    # with open("./config.yaml", "r") as f:
    #     config = yaml.safe_load(f)["work"]
    
    # gdb.rbreak(config["breakpoint_regex"])

    # with open("Todo_Funcs.txt", "r") as f:
    #     todo_funcs = f.read().strip().split("\n")
    
    # with open("Finish_Funcs.txt", "r") as f:
    #     finish_funcs = f.read().strip().split("\n")
    
    # working_funcs = list(set(todo_funcs) - set(finish_funcs))
    
    # while(True):
    #     try:
    #         func_name = gdb.selected_frame().function().name
    #         if func_name not in working_funcs:
    #             # TODO: do corruption
    #             pass
            
    #         gdb.execute(f"clear {func_name}")
    #         gdb.execute("disable")
    #         gdb.execute("finish")
    #         gdb.execute("enable")
    #         gdb.execute("continue")
    #     except:
    #         gdb.execute("quit")
    