from libhopper import parse_config, parse_all, analysis
import subprocess, os
import multiprocessing as mp

gen_core_config = "gen_core.yaml"
analysis_config = "analysis.yaml"

def gen_core_dump():
    global gen_core_config, analysis_config

    # Parse configuration
    config = parse_config(gen_core_config)
    test_name = config["test_name"]
    test_env = config["test_env"]

    # Generate core dump
    test_env["GEN_CORE_CONFIG"] = os.getcwd() + "/" + gen_core_config
    test_env["ANALYSIS_CONFIG"] = analysis_config
    curr_env = os.environ.copy()
    curr_env.update(test_env)

    command = ["gdb", "-ex", "source ./libhopper/gen_core.py", "-ex", "quit", test_name]
    subprocess.run(command, env=curr_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # subprocess.run(command, env=curr_env)

if __name__ == "__main__":
    config = parse_config(gen_core_config)
    core_dump_dir = config["core_dump_dir"]
    analysis_config = core_dump_dir + analysis_config
    gen_core_dump()

    # Analyze core dump
    # analysis(analysis_config, 3)
    # for i in range(10, len(parse_all(analysis_config))):
    #     print(f"Analysis {i}")
    #     analysis(analysis_config, i)
    # analysis(analysis_config, 9)
    # with mp.Pool(4) as pool:
    #     pool.starmap(analysis, [(analysis_config, i) for i in range(10)])
