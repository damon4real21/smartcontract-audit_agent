import argparse, json, urllib.request, os, yaml
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

parser = argparse.ArgumentParser()
parser.add_argument("--address", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

with open(os.path.join(os.path.dirname(__file__), '..', 'config', 'focus.yaml')) as f:
    cfg = yaml.safe_load(f)

API_KEY = os.getenv("BSCSCAN_API_KEY")
CHAIN_ID = cfg["chain_id"]

# Use the unified Etherscan V2 endpoint
URL = (f"https://api.etherscan.io/v2/api?module=contract"
       f"&action=getsourcecode&address={args.address}"
       f"&chainid={CHAIN_ID}&apikey={API_KEY}")

try:
    with urllib.request.urlopen(URL, timeout=30) as r:
        data = json.load(r)
    if data.get("status") != "1":
        raise RuntimeError(data.get("message", "unknown error"))
    source = data["result"][0]["SourceCode"]
    if not source:
        raise RuntimeError("Source is empty — contract may not be verified.")
    
    if source.startswith("{"):
        parsed = json.loads(source)
        with open(args.output, "w") as f:
            for file, content in parsed["sources"].items():
                f.write(content["content"] + "\n\n")
    else:
        with open(args.output, "w") as f:
            f.write(source)

    print(f"✅ Source saved to {args.output}")
except Exception as e:
    print(f"❌ Failed: {e}")
    exit(1)
