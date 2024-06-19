from libhopper import analysis, parse_config
import subprocess, os

config_file = "analysis.yaml"

if __name__ == "__main__":
    # Parse configuration
    config = parse_config(config_file)
    core_dump_dir = config["core_dump_dir"]
    test_name = config["test_name"]
    test_env = config["test_env"]

    # Generate core dump
    curr_env = os.environ.copy()
    curr_env.update(test_env)
    command = ["gdb", "-ex", "source ./libhopper/gen_core.py", "-ex", "quit", test_name]
    subprocess.run(command, env=curr_env)

    # Analyze core dump
    analysis()
