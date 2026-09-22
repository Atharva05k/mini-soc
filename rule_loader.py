from pathlib import Path

import yaml

RULE_FILE = (
    Path(__file__).resolve().parent
    / "rules"
    / "authentication.yml"
)


def load_rules():
    with open(RULE_FILE, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file)

    if not config or "rules" not in config:
        raise ValueError("No 'rules' section found in authentication.yml")

    return config["rules"]
