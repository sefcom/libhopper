import yaml

def parse_config(config_file):
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    return config