import yaml

def parse_config(config_file):
    with open(config_file, "r") as f:
        config = yaml.safe_load(f)
    return config

def parse_all(config_file):
    with open(config_file, "r") as f:
        config = list(yaml.load_all(f, Loader=yaml.SafeLoader))
    return config