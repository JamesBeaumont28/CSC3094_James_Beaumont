import socket
import struct
import json
import time
import threading
import warnings
import os
import ssl
from pathlib import Path
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# suppress harmless deprecation warnings from cryptography library
warnings.filterwarnings("ignore", category=DeprecationWarning)


# info for HTTPS request
RESEARCHER_ID = (
    "Newcastle University School of Computing PQC Survey | "
    "Contact: J.Beaumont2@ncl.ac.uk | "
    "This is academic security research scanning for post-quantum TLS support"
)

# HTTP request sent after the TLS handshake so server operators can identify the scan
# wrote http request parts with the help of claude
HTTP_IDENT_REQUEST = (
    "HEAD / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: NCL-PQC-Scanner/1.0 (Academic Research; Newcastle University)\r\n"
    "From: J.Beaumont2@ncl.ac.uk\r\n"
    "X-Research-Contact: J.Beaumont2@ncl.ac.uk\r\n"
    "X-Scanner-Info: Newcastle University School of Computing PQC Survey\r\n"
    "Connection: close\r\n\r\n"
)

# TLS record and handshake type constants
TLS_VERSION_12         = b'\x03\x03'
HANDSHAKE_CLIENT_HELLO = 0x01
CONTENT_TYPE_HANDSHAKE = 0x16

# IANA group codes for all key exchange groups were looknig for
# classical groups are included so the server can fall back if it does not support PQC
NAMED_GROUPS = {
    # classical
    "X25519":                   0x001D,
    "secp256r1":                0x0017,
    "secp384r1":                0x0018,
    # hybrid ML KEM (NIST FIPS 203 standard)
    "X25519MLKEM768":           0x11EC,
    "SecP256r1MLKEM768":        0x11EB,
    # pure ML KEM
    "MLKEM512":                 0x0200,
    "MLKEM768":                 0x0201,
    "MLKEM1024":                0x0202,
    # legacy Kyber draft codes used by Cloudflare and Google before standardisation
    "X25519Kyber768Draft00":    0x6399,
    "SecP256r1Kyber768Draft00": 0x639A,
}

# reverse lookup used when parsing the ServerHello to get a name from a code
CODE_TO_NAME = {v: k for k, v in NAMED_GROUPS.items()}

# set of group names considered post quantum for has_pqc flagging
PQC_GROUPS = {
    "X25519MLKEM768", "SecP256r1MLKEM768",
    "MLKEM512", "MLKEM768", "MLKEM1024",
    "X25519Kyber768Draft00", "SecP256r1Kyber768Draft00",
}

# PQC groups ordered by real world prevalence so we detect the most common ones first
# this reduces the number of follow-up probes needed on average
# order is based on deployment data: X25519MLKEM768 dominates (Cloudflare, Google),
# legacy Kyber draft is second, pure ML-KEM and SecP256r1 variants are rare
PQC_PROBE_ORDER = [
    NAMED_GROUPS["X25519MLKEM768"],           # most common - deployed by Cloudflare and Google
    NAMED_GROUPS["X25519Kyber768Draft00"],     # second most common - legacy Cloudflare/Google
    NAMED_GROUPS["SecP256r1MLKEM768"],         # rare - P256 hybrid variant
    NAMED_GROUPS["SecP256r1Kyber768Draft00"],  # rare - P256 legacy hybrid
    NAMED_GROUPS["MLKEM768"],                  # rare - pure ML-KEM without classical hybrid
    NAMED_GROUPS["MLKEM1024"],                 # rare - pure ML-KEM high security
    NAMED_GROUPS["MLKEM512"],                  # rare - pure ML-KEM low security
]

# full advertised group list: PQC in prevalence order first, then classical fallbacks
ADVERTISED_GROUPS = PQC_PROBE_ORDER + [
    NAMED_GROUPS["X25519"],
    NAMED_GROUPS["secp256r1"],
    NAMED_GROUPS["secp384r1"],
]

# cipher suites advertised in the ClientHello
# server picks one from this list
CIPHER_SUITES = [
    0x1301,  # TLS_AES_128_GCM_SHA256
    0x1302,  # TLS_AES_256_GCM_SHA384
    0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
]

# signature algorithms advertised in the ClientHello
SIG_ALGS = [
    0x0403,  # ecdsa_secp256r1_sha256
    0x0503,  # ecdsa_secp384r1_sha384
    0x0603,  # ecdsa_secp521r1_sha512
    0x0804,  # rsa_pss_rsae_sha256
    0x0805,  # rsa_pss_rsae_sha384
    0x0806,  # rsa_pss_rsae_sha512
    0x0401,  # rsa_pkcs1_sha256
    0x0501,  # rsa_pkcs1_sha384
    0x0601,  # rsa_pkcs1_sha512
]

# token bucket that limits how many DNS lookups per second all workers can make combined
class DNSRateLimiter:

    def __init__(self, rate: int):
        self.rate        = rate
        self.tokens      = float(rate)
        self.last_refill = time.monotonic()
        self.lock        = threading.Lock()

    def acquire(self):
        # blocks the calling thread until a token is available
        while True:
            with self.lock:
                now     = time.monotonic()
                elapsed = now - self.last_refill

                # add tokens based on how much time has passed
                self.tokens      = min(self.rate, self.tokens + elapsed * self.rate)
                self.last_refill = now

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return

            # no token available yet, wait briefly before retrying
            time.sleep(0.01)

def build_client_hello(hostname: str) -> bytes:
    # builds a TLS 1.3 ClientHello packet advertising all PQC and classical groups

    random_bytes = os.urandom(32)
    session_id   = os.urandom(32)

    # pack cipher suites as a length prefixed list of 2 byte codes
    cs_bytes      = b"".join(struct.pack("!H", cs) for cs in CIPHER_SUITES)
    cipher_suites = struct.pack("!H", len(cs_bytes)) + cs_bytes

    # no compression
    compression = b"\x01\x00"

    # SNI extension tells the server which domain we want
    # without this many servers won't respond correctly
    sni_name  = hostname.encode()
    sni_entry = struct.pack("!BH", 0, len(sni_name)) + sni_name
    sni_list  = struct.pack("!H", len(sni_entry)) + sni_entry
    ext_sni   = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # supported_versions extension is how TLS 1.3 is actually requested
    # the record header uses TLS 1.2 for backwards compatibility
    versions     = struct.pack("!HH", 0x0304, 0x0303)
    ext_versions = struct.pack("!HHB", 0x002B, len(versions) + 1, len(versions)) + versions

    # supported_groups extension lists all key exchange groups we claim to support
    # including PQC groups so the server knows it can select them
    groups_bytes = b"".join(struct.pack("!H", g) for g in ADVERTISED_GROUPS)
    groups_list  = struct.pack("!H", len(groups_bytes)) + groups_bytes
    ext_groups   = struct.pack("!HH", 0x000A, len(groups_list)) + groups_list

    # signature algorithms extension
    sig_bytes   = b"".join(struct.pack("!H", s) for s in SIG_ALGS)
    sig_list    = struct.pack("!H", len(sig_bytes)) + sig_bytes
    ext_sigalgs = struct.pack("!HH", 0x000D, len(sig_list)) + sig_list

    # key_share extension sends an initial X25519 public key as an optimistic guess
    # we use random bytes instead of a real keypair since we never complete the handshake
    ks_key_data  = os.urandom(32)
    ks_entry     = struct.pack("!HH", 0x001D, len(ks_key_data)) + ks_key_data
    ks_list      = struct.pack("!H", len(ks_entry)) + ks_entry
    ext_keyshare = struct.pack("!HH", 0x0033, len(ks_list)) + ks_list

    # ALPN extension advertises supported application protocols
    alpn_protos = b"\x02h2\x08http/1.1"
    alpn_list   = struct.pack("!H", len(alpn_protos)) + alpn_protos
    ext_alpn    = struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list

    # join all extensions into a single length prefixed block
    extensions = ext_sni + ext_versions + ext_groups + ext_sigalgs + ext_keyshare + ext_alpn
    ext_block  = struct.pack("!H", len(extensions)) + extensions

    # ClientHello body: legacy version + random + session id + ciphers + compression + extensions
    hello_body = (
        TLS_VERSION_12 +
        random_bytes +
        struct.pack("B", len(session_id)) + session_id +
        cipher_suites +
        compression +
        ext_block
    )

    # handshake header: type byte + 3 byte length (TLS uses 3 bytes here not 4)
    handshake = (
        struct.pack("B", HANDSHAKE_CLIENT_HELLO) +
        struct.pack("!I", len(hello_body))[1:] +
        hello_body
    )

    # outer TLS record: content type + legacy version + 2 byte length + handshake
    record = (
        bytes([CONTENT_TYPE_HANDSHAKE]) +
        TLS_VERSION_12 +
        struct.pack("!H", len(handshake)) +
        handshake
    )

    return record


def build_client_hello_groups(hostname: str, groups: list) -> bytes:
    # same as build_client_hello but accepts a custom group list
    # used when re-probing after removing already detected PQC groups

    random_bytes  = os.urandom(32)
    session_id    = os.urandom(32)

    cs_bytes      = b"".join(struct.pack("!H", cs) for cs in CIPHER_SUITES)
    cipher_suites = struct.pack("!H", len(cs_bytes)) + cs_bytes
    compression   = b"\x01\x00"

    sni_name  = hostname.encode()
    sni_entry = struct.pack("!BH", 0, len(sni_name)) + sni_name
    sni_list  = struct.pack("!H", len(sni_entry)) + sni_entry
    ext_sni   = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    versions     = struct.pack("!HH", 0x0304, 0x0303)
    ext_versions = struct.pack("!HHB", 0x002B, len(versions) + 1, len(versions)) + versions

    groups_bytes = b"".join(struct.pack("!H", g) for g in groups)
    groups_list  = struct.pack("!H", len(groups_bytes)) + groups_bytes
    ext_groups   = struct.pack("!HH", 0x000A, len(groups_list)) + groups_list

    sig_bytes   = b"".join(struct.pack("!H", s) for s in SIG_ALGS)
    sig_list    = struct.pack("!H", len(sig_bytes)) + sig_bytes
    ext_sigalgs = struct.pack("!HH", 0x000D, len(sig_list)) + sig_list

    ks_key_data  = os.urandom(32)
    ks_entry     = struct.pack("!HH", 0x001D, len(ks_key_data)) + ks_key_data
    ks_list      = struct.pack("!H", len(ks_entry)) + ks_entry
    ext_keyshare = struct.pack("!HH", 0x0033, len(ks_list)) + ks_list

    alpn_protos = b"\x02h2\x08http/1.1"
    alpn_list   = struct.pack("!H", len(alpn_protos)) + alpn_protos
    ext_alpn    = struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list

    extensions = ext_sni + ext_versions + ext_groups + ext_sigalgs + ext_keyshare + ext_alpn
    ext_block  = struct.pack("!H", len(extensions)) + extensions

    hello_body = (
        TLS_VERSION_12 +
        random_bytes +
        struct.pack("B", len(session_id)) + session_id +
        cipher_suites +
        compression +
        ext_block
    )

    handshake = (
        struct.pack("B", HANDSHAKE_CLIENT_HELLO) +
        struct.pack("!I", len(hello_body))[1:] +
        hello_body
    )

    return (
        bytes([CONTENT_TYPE_HANDSHAKE]) +
        TLS_VERSION_12 +
        struct.pack("!H", len(handshake)) +
        handshake
    )


def raw_handshake(ip: str, hostname: str, groups: list, timeout: int) -> dict:
    # opens a raw TCP connection, sends a ClientHello with the given group list,
    # reads the ServerHello and returns the parsed result

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, 443))
    except (ConnectionRefusedError, OSError):
        return {"status": "connect_failed"}

    sock.sendall(build_client_hello_groups(hostname, groups))

    # read the full TLS record based on the length in the record header
    response = b""
    try:
        while len(response) < 5:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        if len(response) >= 5:
            record_len = struct.unpack("!H", response[3:5])[0]
            target = 5 + record_len
            while len(response) < target:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
    except socket.timeout:
        pass
    finally:
        sock.close()

    if not response:
        return {"status": "no_response"}

    parsed           = parse_server_hello(response)
    parsed["status"] = "ok"
    return parsed


def parse_server_hello(data: bytes) -> dict:
    # parses the raw bytes of a TLS ServerHello response
    # extracts the negotiated version, cipher suite and key share group
    # the key share group tells us whether the server selected a PQC group

    result = {
        "tls_version":          None,
        "cipher_suite":         None,
        "key_share_group":      None,
        "key_share_group_name": None,
        "status_detail":        None,
    }

    try:
        if len(data) < 5:
            result["status_detail"] = "response_too_short"
            return result

        content_type = data[0]

        # content type 21 is a TLS alert, meaning the server rejected our ClientHello
        if content_type == 0x15:
            alert_desc = data[6] if len(data) > 6 else 0
            result["status_detail"] = f"tls_alert_{alert_desc}"
            return result

        if content_type != CONTENT_TYPE_HANDSHAKE:
            result["status_detail"] = f"unexpected_content_type_{content_type}"
            return result

        pos = 5

        if len(data) < pos + 4:
            result["status_detail"] = "truncated_handshake"
            return result

        hs_type = data[pos]
        pos += 1

        # handshake length is 3 bytes in TLS, so we pad with a zero byte to unpack as 4
        hs_len = struct.unpack("!I", b'\x00' + data[pos:pos + 3])[0]
        pos += 3

        if hs_type != 0x02:
            result["status_detail"] = f"unexpected_hs_type_{hs_type}"
            return result

        # skip legacy version field (2 bytes) and random (32 bytes)
        pos += 34

        # skip session id
        if pos >= len(data):
            result["status_detail"] = "truncated_session_id"
            return result
        sid_len = data[pos]
        pos += 1 + sid_len

        # read cipher suite
        cs = struct.unpack("!H", data[pos:pos + 2])[0]
        result["cipher_suite"] = hex(cs)
        pos += 2

        # skip compression method
        pos += 1

        # no extensions means this is a TLS 1.2 response
        if pos + 2 > len(data):
            result["tls_version"]   = "TLSv1.2"
            result["status_detail"] = "tls12_no_extensions"
            return result

        ext_total = struct.unpack("!H", data[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack("!H", data[pos:pos + 2])[0]
            ext_len  = struct.unpack("!H", data[pos + 2:pos + 4])[0]
            ext_data = data[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len

            # supported_versions extension contains the actual negotiated TLS version
            if ext_type == 0x002B and len(ext_data) >= 2:
                ver = struct.unpack("!H", ext_data[:2])[0]
                result["tls_version"] = {
                    0x0304: "TLSv1.3",
                    0x0303: "TLSv1.2",
                    0x0302: "TLSv1.1",
                    0x0301: "TLSv1.0",
                }.get(ver, hex(ver))

            # key_share extension contains the group the server selected
            # if this is a PQC group the server supports post quantum key exchange
            if ext_type == 0x0033 and len(ext_data) >= 2:
                group_code = struct.unpack("!H", ext_data[:2])[0]
                result["key_share_group"]      = hex(group_code)
                result["key_share_group_name"] = CODE_TO_NAME.get(group_code, f"unknown_0x{group_code:04x}")

        # if no supported_versions extension was present this is TLS 1.2
        if result["tls_version"] is None:
            result["tls_version"] = "TLSv1.2"

    except Exception as e:
        result["status_detail"] = f"parse_error: {type(e).__name__}"

    return result


def scan_domain(domain: str, timeout: int = 10, dns_limiter: DNSRateLimiter = None) -> dict:
    # scans a single domain for all supported PQC key exchange groups
    # first probe advertises all groups, server picks its preferred PQC group
    # subsequent probes remove already found groups, forcing the server to reveal its next preference
    # stops when the server stops picking a PQC group or a probe fails
    # then sends an identified HTTP request so server operators know who is scanning

    base = {
        "domain":               domain,
        "ip":                   None,
        "status":               None,
        "status_detail":        None,
        "tls_version":          None,
        "cipher_suite":         None,
        "pqc_groups_supported": [],
        "has_pqc":              False,
        "probe_count":          0,
    }

    try:
        # wait for a DNS token before resolving to stay within the rate limit
        try:
            if dns_limiter:
                dns_limiter.acquire()
            addr_info  = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
            ip         = addr_info[0][4][0]
            base["ip"] = ip
        except socket.gaierror:
            return {**base, "status": "dns_error"}

        # track which PQC groups we have confirmed so far
        # start with all groups advertised, remove each one as the server selects it
        remaining_groups = ADVERTISED_GROUPS[:]
        pqc_found        = []
        tls_version      = None
        cipher_suite     = None
        status_detail    = None
        probe_count      = 0

        while True:
            result      = raw_handshake(ip, domain, remaining_groups, timeout)
            probe_count += 1

            if result["status"] != "ok":
                # if the very first probe fails, the domain is unreachable
                if probe_count == 1:
                    return {**base, "status": result["status"]}
                # if a follow-up probe fails, stop here and use what we already found
                break

            # capture version and cipher from the first probe only
            if probe_count == 1:
                tls_version   = result.get("tls_version")
                cipher_suite  = result.get("cipher_suite")
                status_detail = result.get("status_detail")

            group_name = result.get("key_share_group_name")

            # if the server did not select a PQC group we have found everything it supports
            if group_name not in PQC_GROUPS:
                break

            pqc_found.append(group_name)

            # remove the detected group from the list so the server is forced to choose another
            group_code       = NAMED_GROUPS[group_name]
            remaining_groups = [g for g in remaining_groups if g != group_code]

            # stop if there are no PQC groups left to probe for
            if not any(g in remaining_groups for g in PQC_PROBE_ORDER):
                break
            #addded to try deduce error count
            time.sleep(0.3)
        # send a proper HTTPS request with researcher identification headers
        # this is best effort so failures here do not affect the scan result
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((ip, 443), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=domain) as ssock:
                    ssock.sendall(HTTP_IDENT_REQUEST.format(host=domain).encode())
                    ssock.recv(256)
        except Exception:
            pass

        return {
            **base,
            "status":               "ok",
            "status_detail":        status_detail,
            "tls_version":          tls_version,
            "cipher_suite":         cipher_suite,
            "pqc_groups_supported": pqc_found,
            "has_pqc":              len(pqc_found) > 0,
            "probe_count":          probe_count,
        }

    except socket.timeout:
        return {**base, "status": "timeout"}
    except Exception as e:
        return {**base, "status": f"error: {type(e).__name__}"}


def main(
    targets_path="../ingested-data/domains_1.csv",
    out_path="../results/pqc_results_2.jsonl",
    workers=100,
    timeout=10,
    window_size=500,
    stop_ratio=0.6,
    min_seen=500,
    start_from=0,
    dns_rate_limit=75,
):
    targets_file = Path(targets_path)
    out_file     = Path(out_path)

    # ensure input file exists
    if not targets_file.exists():
        print(f"Missing {targets_file}")
        return

    # parse CSV rows such as:
    # 1,google.com
    # keeping the rank number alongside the domain
    targets = []
    for line in targets_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) == 2:
            try:
                rank = int(parts[0].strip())
            except ValueError:
                rank = None
            targets.append((rank, parts[1].strip()))
        else:
            targets.append((None, line))

    if not targets:
        print("No targets found.")
        return

    # skip already scanned domains if resuming a previous run
    if start_from > 0:
        print(f"Resuming from domain {start_from + 1}...")
        targets = targets[start_from:]

    total_overall = start_from + len(targets)
    total         = len(targets)
    print(f"Loaded {total} targets ({total_overall} total), starting {workers} workers...")

    # clear the output file when starting fresh, append when resuming
    if start_from == 0:
        out_file.write_text("", encoding="utf-8")

    totals      = Counter()
    rolling     = []
    lock        = threading.Lock()
    stop_event  = threading.Event()
    start_time  = time.time()
    dns_limiter = DNSRateLimiter(rate=dns_rate_limit)

    def process(item: tuple):
        rank, domain = item

        if stop_event.is_set():
            return

        result         = scan_domain(domain, timeout=timeout, dns_limiter=dns_limiter)
        result["rank"] = rank

        with lock:
            # write result immediately so progress is not lost if scan is interrupted
            with out_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(result) + "\n")

            # update values for progress display
            totals["done"] += 1
            status = result["status"]

            if status == "ok":
                totals["success"] += 1
                rolling.append("success")
            else:
                totals[status] += 1
                rolling.append("error")

            if result["has_pqc"]:
                totals["pqc_found"] += 1
                # count each supported PQC group individually for the breakdown
                for group in result.get("pqc_groups_supported", []):
                    totals[f"pqc:{group}"] += 1

            # trim rolling window to the configured size
            if len(rolling) > window_size:
                del rolling[:-window_size]

            # stop scan if error rate exceeds threshold
            if totals["done"] >= min_seen:
                window     = rolling[-window_size:]
                error_frac = window.count("error") / len(window) if window else 0
                if error_frac >= stop_ratio:
                    print(f"\nStopping: error rate {error_frac:.1%} exceeded {stop_ratio:.1%}.")
                    stop_event.set()

    # progress display runs in its own thread so it doesn't block workers
    def show_progress():
        while not stop_event.is_set():
            time.sleep(1)
            with lock:
                done       = totals["done"]
                window     = rolling[-window_size:]
                error_frac = window.count("error") / len(window) if window else 0.0

            elapsed   = time.time() - start_time
            rate      = done / elapsed if elapsed > 0 else 0
            remaining = (total - done) / rate if rate > 0 else 0
            pct       = done / total * 100 if total else 0
            overall   = start_from + done

            bar_width = 30
            filled    = int(bar_width * done / total) if total else 0
            bar       = "#" * filled + "-" * (bar_width - filled)

            print(
                f"\r[{bar}] {overall}/{total_overall} ({pct:.1f}%) --- "
                f"Rate={rate:.1f}/s --- "
                f"ETA={remaining / 60:.1f}min --- "
                f"PQC={totals['pqc_found']} --- "
                f"Error rate={error_frac:.1%} --- "
                f"DNS limit={dns_rate_limit}/s",
                end="", flush=True,
            )

            if done >= total:
                break

    progress_thread = threading.Thread(target=show_progress, daemon=True)
    progress_thread.start()

    # starts and stops all worker instances, also stops them if error rate is exceeded
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(process, item): item for item in targets}
            for future in as_completed(futures):
                if stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    future.result()
                except Exception:
                    pass
    # except is here to stop incomplete writes to output file in case of interruption
    except KeyboardInterrupt:
        print("\nInterrupted.")
        stop_event.set()

    progress_thread.join(timeout=2)
    elapsed = time.time() - start_time

    print(f"\n\nDone in {elapsed:.1f}s")
    print(f"  Total scanned : {totals['done']}")
    print(f"  Successful    : {totals['success']}")
    print(f"  PQC found     : {totals['pqc_found']}")

    # print breakdown of which PQC groups were found
    pqc_keys = [k for k in totals if k.startswith("pqc:")]
    if pqc_keys:
        print(f"\n  PQC group breakdown:")
        for k in sorted(pqc_keys):
            print(f"    {k.replace('pqc:', '')}: {totals[k]}")

    print(f"\n  Error breakdown:")
    print(f"    dns_error    : {totals['dns_error']}")
    print(f"    connect_fail : {totals['connect_failed']}")
    print(f"    timeout      : {totals['timeout']}")
    print(f"    no_response  : {totals['no_response']}")
    for k, v in totals.items():
        if k.startswith("error:"):
            print(f"    {k}: {v}")

    print(f"\n  Output: {out_file}")


if __name__ == "__main__":
    main(
        targets_path="../ingested-data/domains_1.csv",
        out_path="../results/pqc_results_1.jsonl",
        workers=400,
        timeout=10,
        dns_rate_limit=75,
        start_from=0,
    )