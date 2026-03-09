import json
import subprocess
import sys
import time
from collections import Counter, deque
from pathlib import Path
import threading

def classify_error(err: str) -> str:
    e = err.lower()

    #converts error to lower case string and reads text to find the error type
    # DNS
    if "no such host" in e or "nxdomain" in e:
        return "dns_error"

    # TCP connect
    if "connection refused" in e:
        return "connect_refused"
    if "network is unreachable" in e or "no route to host" in e:
        return "network_unreachable"
    if "connection reset" in e:
        return "connection_reset"
    if "i/o timeout" in e or "timed out" in e:
        return "timeout"

    # TLS
    if "tls" in e and "alert" in e:
        return "tls_alert"
    if "handshake failure" in e:
        return "tls_handshake_failure"
    if "protocol version" in e:
        return "tls_protocol_version"
    if "unexpected eof" in e or e.strip() == "eof" or " eof" in e:
        return "tls_eof"

    # Cert
    if "x509" in e or "certificate" in e:
        return "cert_error"

    return "other"

def get_error(obj: dict) -> str | None:
    # zgrab2 error locations vary by module/version trying to narrow down
    candidates = [
        obj.get("error"),
        obj.get("data", {}).get("tls", {}).get("error"),
        obj.get("data", {}).get("tls", {}).get("result", {}).get("error"),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip():
            return c.strip()
    return None

def main(
    #key info
    targets_path="../ingested-data/domains_1.csv",
    out_path="../ingested-data/tls_results.jsonl",
    window_size=50,
    stop_category="timeout",
    #percentage of failed connections to stop
    stop_ratio=0.01,
    #minimum scans before stopping
    min_seen=10,
    #how often the progress is updated
    report_every=50,
    #caps the number of domains given to the ZGrab instance very second
    rate_limit = 10,
):
    print("hello world")
    targets_file = Path(targets_path)
    out_file = Path(out_path)


    #check the targets exist and are in a readable format
    if not targets_file.exists():
        print(f"Missing {targets_file}")
        sys.exit(1)

    targets = []
    #removes ranking numbers from input ie: 1,"google.com" becomes "google.com"
    for line in targets_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split(",", 1)
        if len(parts) == 2:
            targets.append(parts[1].strip())
        else:
            targets.append(line)

    if not targets:
        print("Targets file empty, input is likely empty too.")
        sys.exit(1)

    #the structure of the command to initialize docker and run ZGrab2
    cmd = [
        "docker", "compose", "run", "--rm", "-T", "zgrab2",
        "tls",
        "--port", "443",
    ]

    print("Starting:", " ".join(cmd))

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    #verifys the input, output and error log exist otherwise it errors
    assert proc.stdin and proc.stdout and proc.stderr

    def feed_targets():
        # gives zgrab domains at a caped rate
        delay = 1 / rate_limit if rate_limit > 0 else 0

        for target in targets:
            if stop_scan:
                break
            proc.stdin.write(target + "\n")
            proc.stdin.flush()
            time.sleep(delay)
        proc.stdin.close()

    #runs the feeder simultaneously to the rest of the code
    stop_scan = False
    feeder = threading.Thread(target=feed_targets)
    feeder.start()

    #info for progress check
    rolling = deque(maxlen=window_size)
    totals = Counter()
    start = time.time()
    seen = 0

    with out_file.open("w", encoding="utf-8") as fout:
        for line in proc.stdout:
            if not line.strip():
                continue

            fout.write(line)
            seen += 1

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                totals["bad_json"] += 1
                rolling.append("bad_json")
                continue

            err = get_error(obj)
            if err:
                cat = classify_error(err)
            else:
                cat = "success"

            totals[cat] += 1
            rolling.append(cat)

            if seen % report_every == 0:
                elapsed = time.time() - start
                rate = seen / elapsed if elapsed > 0 else 0.0
                window_counts = Counter(rolling)
                window_total = len(rolling)
                stop_frac = (window_counts[stop_category] / window_total) if window_total else 0.0
                print(
                    f"seen={seen} rate={rate:.1f}/s "
                    f"window({window_total}) {stop_category}={stop_frac:.1%} "
                    f"totals success={totals['success']} timeout={totals['timeout']} "
                    f"refused={totals['connect_refused']} dns={totals['dns_error']}"
                )

                if seen >= min_seen and window_total == window_size and stop_frac >= stop_ratio:
                    print(
                        f"Stopping: rolling {stop_category} fraction {stop_frac:.1%} "
                        f"exceeded threshold {stop_ratio:.1%}."
                    )
                    stop_scan= True
                    proc.terminate()
                    #print("--------------------------------termination line has ran-----------------------------")
                    break

        # Collect stderr for debugging
        try:
            stderr = proc.stderr.read()
        except Exception:
            stderr = ""

        rc = proc.wait(timeout=15)
        print(f"zgrab2 exited rc={rc}")
        if rc != 0 and stderr.strip():
            print("stderr:\n", stderr[:4000])

if __name__ == "__main__":
    # Defaults stop on too many timeouts, which is a better “something is wrong” signal than refused.
    main()