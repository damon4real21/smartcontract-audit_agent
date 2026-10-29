import subprocess, json, os, urllib.request, time
from dotenv import load_dotenv

load_dotenv()
ALCHEMY_URL = os.getenv("ALCHEMY_BNB_URL")
PROCESSED_FILE = "processed.json"

print("🚀 Starting FULL Automated BNB Audit Pipeline (All Tools)")

if os.path.exists(PROCESSED_FILE):
    with open(PROCESSED_FILE, "r") as f:
        processed_addresses = set(json.load(f))
else:
    processed_addresses = set()

while True:
    try:
        # 1. Fetch Targets ($5k to $1M TVL)
        print("\n[1] Fetching NEW BNB protocols with $5k - $1M TVL...")
        url = "https://api.llama.fi/protocols"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as r:
            protocols = json.load(r)

        targets = []
        for p in protocols:
            chain_tvls = p.get("chainTvls", {})
            bsc_tvl = chain_tvls.get("BSC") or chain_tvls.get("Binance") or chain_tvls.get("bsc") or 0

            if isinstance(bsc_tvl, dict):
                bsc_tvl = bsc_tvl.get("tvl", 0)
            if not isinstance(bsc_tvl, (int, float)):
                continue

            if 5000 <= bsc_tvl <= 1000000:
                addr = p.get("address")
                if not addr:
                    slug = p.get("slug")
                    if slug:
                        try:
                            detail_url = f"https://api.llama.fi/protocol/{slug}"
                            with urllib.request.urlopen(detail_url, timeout=10) as r2:
                                detail = json.load(r2)
                            addr = detail.get("address")
                        except Exception:
                            pass

                if addr and isinstance(addr, str):
                    clean_addr = addr
                    if ":" in addr:
                        prefix, clean_addr = addr.split(":", 1)
                        if prefix.lower() not in ["bsc", "binance"]:
                            continue

                    if clean_addr.startswith("0x") and clean_addr not in processed_addresses:
                        targets.append({
                            "name": p["name"].replace(" ", "_").replace("/", "_").replace("'", ""),
                            "address": clean_addr,
                            "tvl": bsc_tvl
                        })

        if not targets:
            print("⚠️ No NEW targets found. Waiting 1 minute...")
            time.sleep(60)
            continue

        MAX_TARGETS = 5
        targets = targets[:MAX_TARGETS]
        print(f"✅ Found {len(targets)} NEW targets to audit.")

        # 2. Sequential Audit Loop
        for t in targets:
            name, addr, tvl = t["name"], t["address"], t["tvl"]
            print(f"\n==============================================")
            print(f"🎯 Auditing {name} ({addr}) | TVL: ${tvl:,.2f}")
            print(f"==============================================")

            processed_addresses.add(addr)
            with open(PROCESSED_FILE, "w") as f:
                json.dump(list(processed_addresses), f)

            sol_file = f"contracts/{name}.sol"

            # A. Fetch Source or Decompile
            print(f"[A] Fetching source from Etherscan...")
            res = subprocess.run(["python", "scripts/fetch_source_bsc.py", "--address", addr, "--output", sol_file], shell=True)

            if res.returncode != 0:
                print("⚠️ Source not verified. Switching to local sevm decompilation...")
                try:
                    hex_file = f"contracts/{name}.hex"
                    cast_cmd = ["cast", "code", addr, "--rpc-url", ALCHEMY_URL]
                    with open(hex_file, "w") as f:
                        subprocess.run(cast_cmd, stdout=f, check=True, shell=True)

                    with open(hex_file, "r") as f:
                        bytecode = f.read().strip()

                    if not bytecode or bytecode == "0x":
                        print("❌ Bytecode empty. Skipping.")
                        continue

                    print(f"[A.2] Decompiling via sevm...")
                    temp_sol = f"contracts/{name}_decompiled.sol"
                    sevm_cmd = ["sevm", "sol", hex_file]
                    result = subprocess.run(sevm_cmd, capture_output=True, text=True, shell=True)

                    if result.returncode == 0 and result.stdout:
                        with open(temp_sol, "w") as f:
                            f.write(result.stdout)
                        sol_file = temp_sol
                        print(f"✅ Decompiled code saved.")
                    else:
                        print(f"❌ sevm failed. Skipping.")
                        continue
                except Exception as e:
                    print(f"❌ Decompilation failed: {e}. Skipping.")
                    continue

            # B. Run All Static Analyzers Sequentially
            print(f"[B.1] Running Slither...")
            slither_out = f"reports/slither_{name}.json"
            subprocess.run(["slither", sol_file, "--detect", "missing-access-control,unprotected-upgrade,dos-loop,return-bomb", "--json", slither_out], capture_output=True, shell=True)

            print(f"[B.2] Running Aderyn...")
            aderyn_out = f"reports/aderyn_{name}.json"
            subprocess.run(["aderyn", sol_file, "-o", aderyn_out], capture_output=True, shell=True)

            print(f"[B.3] Running ChainEDR...")
            chainedr_out = f"reports/chainedr_{name}.json"
            subprocess.run(["chainedr", "xcheck", sol_file, "--json", chainedr_out], capture_output=True, shell=True)

            print(f"[B.4] Running SolScan...")
            solscan_out = f"reports/solscan_{name}.json"
            subprocess.run(["solscan", sol_file, "--json", solscan_out], capture_output=True, shell=True)

            print(f"[B.5] Running GasProfiler...")
            gasprofiler_out = f"reports/gasprofiler_{name}.json"
            subprocess.run(["gasprofiler", "profile", sol_file, "--format", "json", "--out", gasprofiler_out], capture_output=True, shell=True)

            # C. Combine Outputs for AI
            print(f"[C] Combining findings and running Local AI...")
            combined_findings = f"reports/combined_{name}.json"
            combined_data = {}
            
            for tool_name, filepath in [("slither", slither_out), ("aderyn", aderyn_out), ("chainedr", chainedr_out), ("solscan", solscan_out), ("gasprofiler", gasprofiler_out)]:
                try:
                    if os.path.exists(filepath):
                        with open(filepath, encoding="utf-8") as f:
                            # Handle empty or malformed JSON gracefully
                            content = f.read().strip()
                            if content:
                                combined_data[tool_name] = json.loads(content)
                except Exception as e:
                    print(f"⚠️ Could not read {tool_name} output: {e}")

            with open(combined_findings, "w", encoding="utf-8") as f:
                json.dump(combined_data, f)

            ai_out = f"reports/ai_{name}.json"
            subprocess.run(["python", "scripts/ai_analyze.py", "--findings", combined_findings, "--output", ai_out], shell=True)

            # D. Foundry Verification
            try:
                with open(ai_out, encoding="utf-8") as f:
                    bugs = json.load(f).get("confirmed_bugs", [])

                if len(bugs) > 0:
                    print(f"[D] ⚠️ {len(bugs)} bugs confirmed! Running Foundry Fork Test...")
                    if ALCHEMY_URL:
                        env = os.environ.copy()
                        env["FOUNDRY_FORK_URL"] = ALCHEMY_URL
                        subprocess.run(["npx", "raze", "fuzz", ".", "--contract", name, "--run"], env=env, shell=True)
                    else:
                        print("⚠️ No ALCHEMY_BNB_URL found in .env. Cannot run fork test.")
                else:
                    print(f"[D] ✅ No confirmed bugs.")
            except FileNotFoundError:
                print("[D] AI output not found, skipping Foundry.")

        print(f"\n🏁 Pass complete! Waiting 1 minute before checking for new protocols...")
        time.sleep(60)

    except Exception as e:
        print(f"⚠️ Error occurred: {e}")
        print("Retrying in 1 minute...")
        time.sleep(60)
