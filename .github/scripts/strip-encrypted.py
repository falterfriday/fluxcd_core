import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if isinstance(d, dict) and "sops" not in d]
sys.stdout.write(yaml.safe_dump_all(docs) if docs else "")
