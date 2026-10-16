"""Public-lane log sanitizer.

Reads stdout from scripts/e2b_reg.py line by line and writes a redacted copy
so no cookie/token/credential value can ever land in a public Actions log.

Rules:
- CANARY_RESULT JSON: values of non-allow-listed fields are replaced with
  "[redacted]" (key names are preserved so the shape stays visible).
- Inline redactions on any line: API key prefixes, 6-digit verification codes.
"""
import json
import re
import sys

SAFE_FIELDS = {
    "email",
    "started",
    "ip",
    "ipify_err",
    "reg_flow_state",
    "reg_messages",
    "direct_session",
    "credit",
    "api_test",
    "result",
    "finished",
}

RE_CODES = re.compile(r"(codes (?:\(older msg\) )?from .*: )\[[\d, ]*\]")
RE_VERIFY = re.compile(r"(verify code )\d{6}")
RE_APIKEY = re.compile(r"(API KEY )\S*?\.\.\.")


def sanitize_line(line):
    if line.startswith("CANARY_RESULT "):
        raw = line[len("CANARY_RESULT "):]
        try:
            obj = json.loads(raw)
        except Exception:
            return "CANARY_RESULT [unparseable - redacted]"
        red = {k: (v if k in SAFE_FIELDS else "[redacted]") for k, v in obj.items()}
        return "CANARY_RESULT " + json.dumps(red)
    line = RE_CODES.sub(r"\1[redacted]", line)
    line = RE_VERIFY.sub(r"\1[redacted]", line)
    line = RE_APIKEY.sub(r"\1[redacted]...", line)
    return line


def main():
    for line in sys.stdin:
        sys.stdout.write(sanitize_line(line.rstrip("\r\n")) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
