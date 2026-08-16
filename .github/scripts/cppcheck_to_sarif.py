#!/usr/bin/env python3
"""Convert cppcheck --xml-version=2 output to SARIF 2.1.0.

cppcheck (<= 2.13, the version shipped by Ubuntu runners) has no native SARIF
writer, so this maps its stable XML v2 schema onto the minimal SARIF the
GitHub code-scanning upload accepts. Advisory only: unknown/empty input still
produces a valid empty SARIF run so the upload step never fails the job.
"""
import sys
import xml.etree.ElementTree as ET

SEVERITY_TO_LEVEL = {
    "error": "error",
    "warning": "warning",
    "portability": "note",
    "performance": "note",
    "style": "note",
    "information": "note",
}


def main() -> int:
    in_path = sys.argv[1] if len(sys.argv) > 1 else "cppcheck.xml"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "cppcheck.sarif"

    results = []
    rules = {}
    try:
        tree = ET.parse(in_path)
        for err in tree.getroot().iter("error"):
            rule_id = err.get("id", "cppcheck")
            severity = err.get("severity", "warning")
            level = SEVERITY_TO_LEVEL.get(severity, "warning")
            message = err.get("verbose") or err.get("msg") or rule_id

            loc = err.find("location")
            file_uri = loc.get("file") if loc is not None else "bpf/"
            line = int(loc.get("line", "1")) if loc is not None else 1
            if line < 1:
                line = 1

            rules.setdefault(rule_id, {"id": rule_id, "name": rule_id})
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_uri},
                        "region": {"startLine": line},
                    }
                }],
            })
    except (ET.ParseError, FileNotFoundError) as exc:
        print(f"cppcheck_to_sarif: no parseable input ({exc}); emitting empty run", file=sys.stderr)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "cppcheck", "rules": list(rules.values())}},
            "results": results,
        }],
    }

    import json
    with open(out_path, "w") as f:
        json.dump(sarif, f)
    print(f"cppcheck_to_sarif: wrote {len(results)} result(s) to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
