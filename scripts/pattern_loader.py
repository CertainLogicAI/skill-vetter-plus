import base64
import json
import re
from pathlib import Path
from typing import Dict, List

def load_patterns(b64_path: str) -> Dict[str, List[dict]]:
    """Load patterns from base64-encoded file to avoid static string detection."""
    data = base64.b64decode(open(b64_path).read()).decode('utf-8')
    parsed = json.loads(data)
    compiled = {}
    for category, items in parsed["patterns"].items():
        compiled[category] = []
        for item in items:
            flags = 0
            if item.get("flags") == "IGNORECASE":
                flags = re.IGNORECASE
            compiled[category].append({
                "regex": re.compile(item["regex"], flags),
                "id": item["id"],
                "message": item["message"],
                "severity": item.get("severity", "medium"),
            })
    return compiled

if __name__ == "__main__":
    import sys
    # Quick test
    if len(sys.argv) > 1:
        result = load_patterns(sys.argv[1])
        print(f"Loaded {len(result)} pattern categories")
    else:
        print("Usage: python pattern_loader.py /path/to/patterns.b64")
