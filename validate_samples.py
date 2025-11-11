# scripts/validate_samples.py
import glob, json
doms = glob.glob("samples/*.dom")
print("dom count:", len(doms))
missing = []
for d in doms:
    meta = d.replace(".dom", ".meta.json")
    try:
        j = json.load(open(meta))
        if "label" not in j:
            missing.append(meta)
    except Exception as e:
        missing.append(meta)
print("missing meta or label:", len(missing))
if missing:
    print(missing[:5])
