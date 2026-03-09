import json
import subprocess
import sys
import time
from collections import Counter, deque
from pathlib import Path
import threading


# classify different network / TLS errors into categories
def classify_error(err: str) -> str:
    e = err.lower()

    # DNS
    if "no such host" in e or "nxdomain" in e:
        return "dns_error"

    # TCP connect errors
    if "connection refused" in e:
        return "connect_refused"
    if "network is unreachable" in e or "no route to host" in e:
        return "network_unreachable"
    if "connection reset" in e:
        return "connection_reset"
    if "i/o timeout" in e or "timed out" in e:
        return "timeout"

    # TLS errors
    if "tls" in e and "alert" in e:
        return "tls_alert"
    if "handshake failure" in e:
        return "tls_handshake_failure"
    if "protocol version" in e:
        return "tls_protocol_version"
    if "unexpected eof" in e or e.strip() == "eof" or " eof" in e:
        return "tls_eof"

    # certificate errors
    if "x509" in e or "certificate" in e:
        return "cert_error"

    return "other"


# extract error string from zgrab json
def get_error(obj: dict) -> str | None:
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
    targets_path="../ingested-data/domains_1.csv",
    out_path="../ingested-data/tls_results.jsonl",
    window_size=500,
    stop_category="timeout",
    stop_ratio=0.3,
    min_seen=2000,
    rate_limit=100,
):

    targets_file = Path(targets_path)
    out_file = Path(out_path)

    # ensure input file exists
    if not targets_file.exists():
        print(f"Missing {targets_file}")
        sys.exit(1)

    targets = []

    # convert CSV rows such as:
    # 1,google.com
    # into just:
    # google.com
    for line in targets_file.read_text(encoding="utf-8", errors="replace").splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split(",", 1)

        if len(parts) == 2:
            targets.append(parts[1].strip())
        else:
            targets.append(line)

    # ensure targets exist
    if not targets:
        print("Targets file empty, input is likely empty too.")
        sys.exit(1)

    container_name = "zgrab2"

    # docker command used to run zgrab
    cmd = [
        "docker", "compose", "run", "--rm", "-T", container_name,
        "tls",
        "--port", "443",
    ]

    print("Starting:", " ".join(cmd))

    # start zgrab process
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    assert proc.stdin and proc.stdout and proc.stderr

    # threading control event
    stop_scan = threading.Event()

    # store stderr lines from zgrab
    stderr_lines = []

    # info for progress check
    rolling = deque(maxlen=window_size)
    totals = Counter()
    start = time.time()
    seen = 0
    total_targets = len(targets)

    # update progress roughly once per second based on the send rate
    report_every = max(1, rate_limit)

    # thread to feed targets into zgrab at a rate limit
    def feed_targets():

        delay = 1 / rate_limit if rate_limit > 0 else 0

        for i, target in enumerate(targets):

            # stop feeding if stop condition triggered
            if stop_scan.is_set():
                print("\nerror detected, stopping feeder")
                break

            # rate limiting
            if i != 0 and delay > 0:
                time.sleep(delay)

            try:
                proc.stdin.write(target + "\n")
                proc.stdin.flush()
            except BrokenPipeError:
                break

        # close stdin when finished
        try:
            proc.stdin.close()
        except Exception:
            pass

    # ---------------------------------------------------
    # thread 2 : continuously read stderr
    # prevents pipe buffer blocking
    # ---------------------------------------------------
    def drain_stderr():

        for line in proc.stderr:
            stderr_lines.append(line)

    # start threads
    feeder = threading.Thread(target=feed_targets, daemon=True)
    stderr_thread = threading.Thread(target=drain_stderr, daemon=True)

    feeder.start()
    stderr_thread.start()

    # ---------------------------------------------------
    # main loop reading zgrab stdout
    # ---------------------------------------------------
    with out_file.open("w", encoding="utf-8") as fout:

        for line in proc.stdout:

            if not line.strip():
                continue

            # write raw json output to file
            fout.write(line)

            try:
                obj = json.loads(line)

            except json.JSONDecodeError:
                totals["bad_json"] += 1
                rolling.append("bad_json")
                continue

            # skip only the final summary JSON line
            # real target results have at least a domain or ip
            if "domain" not in obj and "ip" not in obj:
                continue

            err = get_error(obj)

            if err:
                cat = classify_error(err)
            else:
                cat = "success"

            seen += 1
            totals[cat] += 1
            rolling.append(cat)

            window_counts = Counter(rolling)
            window_total = len(rolling)

            failure_count = window_total - window_counts["success"]
            stop_frac = failure_count / window_total if window_total else 0.0

            # update progress display roughly once per second
            if seen % report_every == 0 or seen == total_targets:
                elapsed = time.time() - start
                rate = seen / elapsed if elapsed > 0 else 0.0

                ratio = seen / total_targets if total_targets else 0
                bar_width = 30
                filled = int(bar_width * ratio)
                bar = "#" * filled + "-" * (bar_width - filled)

                print(
                    f"\r[{bar}] {seen}/{total_targets} --- "
                    f"Scan rate={rate:.1f}/s --- "
                    f"Error rate={stop_frac:.1%} --- "
                    f"success={totals['success']} --- "
                    f"timeout={totals['timeout']} --- "
                    f"refused={totals['connect_refused']} --- "
                    f"dns={totals['dns_error']} --- "
                    f"other={totals['other']}",
                    end="",
                    flush=True,
                )

            # stop scan if error threshold exceeded
            if seen >= min_seen and stop_frac >= stop_ratio:
                print(
                    f"\nStopping: rolling {stop_category} fraction {stop_frac:.1%} "
                    f"exceeded threshold {stop_ratio:.1%}."
                )

                stop_scan.set()

                try:
                    proc.stdin.close()
                except Exception:
                    pass

                try:
                    proc.terminate()
                except Exception:
                    pass

                subprocess.run(
                    ["docker", "kill", container_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                break

    feeder.join(timeout=2)
    #stderr_thread.join(timeout=2)

    # wait for zgrab to exit
    try:
        rc = proc.wait(timeout=15)

    except subprocess.TimeoutExpired:
        proc.kill()
        rc = proc.wait()

    print()
    print(f"zgrab2 exited rc={rc}")

    stderr = "".join(stderr_lines).strip()

    # print stderr if zgrab failed
    if rc != 0 and stderr:
        print("stderr:\n", stderr[:4000])


if __name__ == "__main__":
    main()