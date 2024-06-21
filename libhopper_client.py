from libhopper import parse_config
import subprocess, os

gen_core_config = "gen_core.yaml"
analysis_config = "analysis.yaml"

def gen_core_dump():
    # Parse configuration
    config = parse_config(gen_core_config)
    test_name = config["test_name"]
    test_env = config["test_env"]

    # Generate core dump
    test_env["GEN_CORE_CONFIG"] = os.getcwd() + "/" + gen_core_config
    test_env["ANALYSIS_CONFIG"] = os.getcwd() + "/" + analysis_config
    curr_env = os.environ.copy()
    curr_env.update(test_env)

    command = ["gdb", "-ex", "source ./libhopper/gen_core.py", "-ex", "quit", test_name]
    subprocess.run(command, env=curr_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

if __name__ == "__main__":
    gen_core_dump()

    # Analyze core dump
    # for i in len(parse_all(analysis_config)):
    #     analysis(analysis_config, i)
