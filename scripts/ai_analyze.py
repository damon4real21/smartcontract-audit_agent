import argparse, json, subprocess, textwrap, yaml, os

parser = argparse.ArgumentParser()
parser.add_argument("--findings", required=True)
parser.add_argument("--output", required=True)
args = parser.parse_args()

# Load focus config
with open(os.path.join(os.path.dirname(__file__), '..', 'config', 'focus.yaml')) as f:
    cfg = yaml.safe_load(f)

focus = cfg["focus_areas"]
gas_classes = cfg.get("gas_only_classes", [])
threshold = cfg["confidence_threshold"]

focus_text = ""
if "access_control" in focus:
    focus_text += "- ACCESS CONTROL: privileged functions callable by anyone.\n"
if "unlimited_mint" in focus:
    focus_text += "- UNLIMITED MINT: public mint with no supply cap and no access control.\n"
if "gas_only_exploits" in focus:
    focus_text += f"- GAS-ONLY EXPLOITS: bugs where attacker pays only gas. Classes: {', '.join(gas_classes)}\n"

# Load the combined findings from all 5 tools
try:
    with open(args.findings, encoding="utf-8") as f:
        combined_data = json.load(f)
except Exception as e:
    print(f"Failed to load findings: {e}")
    exit(1)

# Flatten all findings into a single list for the AI
all_findings = []
for tool, data in combined_data.items():
    if isinstance(data, dict):
        if "results" in data and isinstance(data["results"], list):
            all_findings.extend(data["results"])
        elif "detectors" in data and isinstance(data["detectors"], list):
            all_findings.extend(data["detectors"])
        elif "issues" in data and isinstance(data["issues"], list):
            all_findings.extend(data["issues"])
    elif isinstance(data, list):
        all_findings.extend(data)

# Filter out low severity to save context window
high = [f for f in all_findings if isinstance(f, dict) and str(f.get("severity", "HIGH")).upper() in ("HIGH", "CRITICAL", "MEDIUM")]

if not high:
    with open(args.output, "w") as f:
        json.dump({"confirmed_bugs": []}, f)
    print("✅ No static findings to analyze.")
    exit(0)

prompt = textwrap.dedent(f"""
You are an expert smart contract auditor. Analyze the following raw tool outputs.
Your goal is to CONFIRM ONLY these bug classes:
{focus_text}

For each confirmed bug, output a JSON object with key "confirmed_bugs".
Each item must have:
  - "function": string
  - "bug_type": "access_control" | "unlimited_mint" | "gas_griefing" | "other"
  - "gas_only": true/false (true ONLY if attacker needs no capital beyond gas)
  - "explanation": string
  - "confidence": float (0.0-1.0)

Discard any finding with confidence < {threshold}.
If a finding requires capital, set gas_only=false and do NOT include it.
If nothing is confirmed, output {{ "confirmed_bugs": [] }}.

Raw Tool Findings:
{json.dumps(high, indent=2)}
""")

print("🧠 Asking local AI (Llama 3.1) to analyze findings...")
# Use shell=True for Windows compatibility with ollama
result = subprocess.run(["ollama", "run", "llama3.1", prompt], capture_output=True, text=True, shell=True)

raw = result.stdout.strip()
start, end = raw.find("{"), raw.rfind("}")
if start != -1 and end != -1:
    raw = raw[start:end+1]

try:
    parsed = json.loads(raw)
    if "confirmed_bugs" in parsed:
        parsed["confirmed_bugs"] = [
            b for b in parsed["confirmed_bugs"]
            if b.get("gas_only") is True and b.get("confidence", 0) >= threshold
        ]
except Exception:
    parsed = {"confirmed_bugs": [], "raw_llm_output": raw}

with open(args.output, "w") as f:
    json.dump(parsed, f, indent=2)

print(f"✅ Confirmed bugs: {len(parsed.get('confirmed_bugs', []))}")
