#!/usr/bin/env python3
"""
network_diagnostics.py

DISCLAIMER: This script was made with AI.

A small test suite for tracking down three kinds of problems on a network:
  - CONNECTIVITY - is the link up at all, and where does it break
    (local IP, gateway, external reachability, DNS, TCP)
  - PERFORMANCE - is the link slow or unstable
    (packet loss/latency, traceroute hop count)
  - SECURITY - does anything here look like a risk worth flagging
    (insecure open services, TLS/MITM interception, ARP spoofing,
    proxy redirection, DNS resolver inconsistency)

Each check is tagged with one of those three categories; the report groups
results accordingly and calls out security findings separately since those
matter even when the connection itself is healthy.

Works on Windows, macOS, and Linux using only the standard library.
"""

import argparse
import concurrent.futures
import ipaddress
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import sys

EXTERNAL_IP = "8.8.8.8"        # Google DNS - reliable external ping target
EXTERNAL_HOST = "google.com"    # Used to test DNS resolution
HTTP_TEST_URL = ("google.com", 443)  # host, port for a basic TCP reachability check

# Public resolvers to cross-check DNS against (name -> IP)
DNS_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
}

# only scanning hosts the user controls (their own machine and
# their own router) to keep this classroom-safe. This list goes beyond the
# handful of "basic" ports to cover services that commonly show up in
# networking/cybersecurity coursework: core web/mail/name services, legacy
# and remote-access protocols that are frequent CTF/pentest-lab targets,
# and databases that are sometimes accidentally exposed.
COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC",
    135: "RPC/DCOM", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    162: "SNMP-trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 500: "IPSec/ISAKMP", 587: "SMTP-submission",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle-DB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    27017: "MongoDB",
}

# flagged as a security finding (rather than just informational)
# because each either transmits credentials/data in plaintext, has a
# history of running with no authentication by default, or is a common
# lateral-movement/exploit target. Grouped by why they're risky:
INSECURE_PORTS = {
    # Plaintext protocols - credentials/data readable to anyone on-path
    21: "FTP", 23: "Telnet", 69: "TFTP", 25: "SMTP", 110: "POP3",
    143: "IMAP", 389: "LDAP", 161: "SNMP",
    # Legacy Windows/RPC services - long exploit history, rarely need to
    # be exposed beyond a trusted local segment
    111: "RPC", 135: "RPC/DCOM", 139: "NetBIOS", 445: "SMB",
    # Remote access - frequent brute-force targets, and VNC in particular
    # is often deployed with weak or no authentication
    3389: "RDP", 5900: "VNC",
    # Databases - if these are reachable from outside localhost at all,
    # that's usually a misconfiguration; several (Redis, MongoDB) shipped
    # with no authentication enabled by default for years
    3306: "MySQL", 1433: "MSSQL", 1521: "Oracle-DB", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB",
}

CONNECTIVITY = "CONNECTIVITY"
PERFORMANCE = "PERFORMANCE"
SECURITY = "SECURITY"

IS_WINDOWS = platform.system().lower() == "windows"

# color is a presentation-layer concern, so it's kept as a
# single module-level flag that main() sets once (from --no-color and
# whether stdout is actually a terminal) rather than threaded through
# every function signature.
COLOR_ENABLED = True

_CODES = {
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "cyan": "\033[36m", "bold": "\033[1m", "reset": "\033[0m",
}


def colorize(text, color):
    if not COLOR_ENABLED:
        return text
    return f"{_CODES[color]}{text}{_CODES['reset']}"


def _enable_windows_ansi():
    """
    Legacy cmd.exe doesn't render ANSI escape codes unless virtual
    terminal processing is turned on explicitly; Windows Terminal and
    PowerShell 7+ already have it on. Best-effort: if this fails (very
    old Windows), color just won't render, which is a graceful decay.
    """
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        pass


def run(label, func, category):
    """Run one diagnostic check and return (label, category, ok, detail)."""
    try:
        ok, detail = func()
    except Exception as e:  # noqa: BLE001 - want to catch/report anything unexpected
        ok, detail = False, f"error: {e}"
    return label, category, ok, detail


def run_all(steps, max_workers=8):
    """
    Run a list of (label, func, category) checks concurrently - they're all
    I/O-bound (subprocess calls, socket connects) so threads give a real
    speedup without needing to rewrite every check as async.
    Prints each result as it finishes, then returns a dict of
    label -> (category, ok, detail) for reporting.
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(run, label, func, category): label
            for label, func, category in steps
        }
        for future in concurrent.futures.as_completed(futures):
            label, category, ok, detail = future.result()
            if ok:
                status = colorize("OK", "green")
            else:
                status = colorize("FAIL", "red")
            print(f"[{status}] {label}: {detail}")
            results[label] = (category, ok, detail)
    return results


def get_local_ip():
    """Return the local IPv4 address used for the default external route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((EXTERNAL_IP, 80))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()

    return ip


def _get_interface_ipv4_addresses():
    """
    Return IPv4 addresses actually assigned to local interfaces.

    Uses platform-native commands because Python's standard library does not
    provide a portable interface-address enumeration API.
    """
    addresses = set()

    try:
        if IS_WINDOWS:
            output = subprocess.check_output(
                ["ipconfig"],
                text=True,
                errors="ignore",
                stderr=subprocess.DEVNULL,
                timeout=5,
            )

            # Matches:
            # IPv4 Address. . . . . . . . . . . : 192.168.1.100
            # Also works with localized output because the IP itself is stable.
            addresses.update(
                re.findall(
                    r"(?:IPv4 Address|IPv4 Address[.\s]*).*?:\s*(\d+\.\d+\.\d+\.\d+)",
                    output,
                    re.IGNORECASE,
                )
            )

            # More permissive fallback for localized Windows output.
            if not addresses:
                addresses.update(
                    re.findall(
                        r":\s*(\d{1,3}(?:\.\d{1,3}){3})",
                        output,
                    )
                )

        else:
            try:
                output = subprocess.check_output(
                    ["ip", "-4", "addr"],
                    text=True,
                    errors="ignore",
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )

                addresses.update(
                    re.findall(
                        r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d+",
                        output,
                    )
                )
            except (FileNotFoundError, subprocess.SubprocessError):
                # macOS/BSD fallback
                output = subprocess.check_output(
                    ["ifconfig"],
                    text=True,
                    errors="ignore",
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )

                addresses.update(
                    re.findall(
                        r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})",
                        output,
                    )
                )

    except Exception:
        return set()

    return addresses


def _is_usable_local_ipv4(ip):
    """Return True only for a normal unicast IPv4 address."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False

    return (
        not addr.is_unspecified
        and not addr.is_loopback
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_link_local
    )


def check_local_ip():
    ip = get_local_ip()

    if not ip:
        return False, "no local IPv4 address could be determined"

    if not _is_usable_local_ipv4(ip):
        return False, f"invalid/unusable local address {ip}"

    interface_addresses = _get_interface_ipv4_addresses()

    if not interface_addresses:
        return False, f"could not verify {ip} against local interfaces"

    if ip not in interface_addresses:
        return False, f"{ip} is not assigned to a local interface"

    return True, ip


def get_default_gateway():
    """
    Best-effort gateway lookup without third-party libraries.
    Tries multiple commands per platform since availability/output format
    varies a lot (e.g. macOS has no `ip` command; some minimal Linux images
    lack iproute2; Windows ipconfig output is locale-dependent).
    """
    if IS_WINDOWS:
        attempts = [
            (["ipconfig"], r"Default Gateway[.\s]*: ([\d.]+)"),
            # fall back to `route print`'s numeric table, which
            # isn't localized like ipconfig's labels are. The 0.0.0.0 row's
            # 3rd column is the gateway.
            (["route", "print", "-4"], r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)"),
        ]
    else:
        attempts = [
            (["ip", "route"], r"default via ([\d.]+)"),
            # macOS / BSD
            (["route", "-n", "get", "default"], r"gateway:\s*([\d.]+)"),
            # Generic Unix fallback if neither of the above exists
            (["netstat", "-rn"], r"^(?:default|0\.0\.0\.0)\s+([\d.]+)"),
        ]

    for cmd, pattern in attempts:
        try:
            out = subprocess.check_output(
                cmd, text=True, errors="ignore",
                stderr=subprocess.DEVNULL, timeout=5,
            )
            match = re.search(pattern, out, re.MULTILINE)
            if match:
                return match.group(1)
        except Exception:
            continue
    return None


def _ping_cmd(host, count, timeout):
    """
    Build a ping command whose flags mean the same thing across OSes.
    macOS's BSD ping and Windows both take -W/-w in
    MILLISECONDS; Linux's iputils ping takes -W in SECONDS. Treating
    macOS like Linux here was a real bug - it turned a 2-second timeout
    into a 2-millisecond one, making nearly every ping fail on macOS.
    """
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    if system == "darwin":
        return ["ping", "-c", str(count), "-W", str(timeout * 1000), host]
    return ["ping", "-c", str(count), "-W", str(timeout), host]  # Linux


def ping(host, count=2, timeout=2):
    """Cross-platform ping wrapper. Returns True if the host responds."""
    result = subprocess.run(
        _ping_cmd(host, count, timeout),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=timeout * count + 5,  # hard stop in case the command hangs
    )
    return result.returncode == 0


def check_gateway():
    gw = get_default_gateway()
    if not gw:
        return False, "could not determine default gateway"
    if ping(gw):
        return True, f"gateway {gw} reachable"
    return False, f"gateway {gw} did not respond"


def check_external_ip():
    if ping(EXTERNAL_IP):
        return True, f"{EXTERNAL_IP} reachable"
    return False, f"{EXTERNAL_IP} did not respond (upstream/ISP issue likely)"


def check_dns():
    try:
        ip = socket.gethostbyname(EXTERNAL_HOST)
        return True, f"{EXTERNAL_HOST} -> {ip}"
    except socket.gaierror as e:
        return False, f"DNS resolution failed ({e})"


def check_tcp_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP connect to {host}:{port} succeeded"
    except OSError as e:
        return False, f"TCP connect to {host}:{port} failed ({e})"


def ping_stats(host, count=6, timeout=2):
    """Run ping and parse packet loss % and avg latency from the output."""
    result = subprocess.run(
        _ping_cmd(host, count, timeout),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=timeout * count + 5,
    )
    out = result.stdout

    loss_match = re.search(r"(\d+)% (?:packet )?loss", out)
    loss = int(loss_match.group(1)) if loss_match else None

    # only bothering to parse avg latency; min/max aren't
    # critical for a basic health check and formats vary too much across
    # Windows/macOS/Linux to parse reliably.
    if IS_WINDOWS:
        avg_match = re.search(r"Average = (\d+)ms", out)
    else:
        avg_match = re.search(r"= [\d.]+/([\d.]+)/", out)  # min/avg/max/mdev
    avg_ms = avg_match.group(1) if avg_match else None
    return loss, avg_ms


def check_packet_loss(host):
    loss, avg_ms = ping_stats(host)
    if loss is None:
        return False, "could not parse ping statistics"
    detail = f"{loss}% packet loss" + (f", avg {avg_ms}ms" if avg_ms else "")
    if loss == 100:
        return False, detail
    if loss > 0:
        return False, detail + " (unstable connection)"
    return True, detail


def query_dns_server(server, hostname, timeout=3):
    """
    Send a minimal A-record query directly to `server` over raw UDP and
    check for a valid answer, using only the standard library socket
    module - no nslookup/dig/host required. This matters because an
    increasing number of Linux distros (and minimal containers) ship
    iproute2 but not bind-utils/dnsutils, so relying on those commands
    being installed isn't safe to assume anymore.

    Returns (ok, detail).
    """
    try:
        # hand-rolling just enough of the DNS wire format for
        # a single-question A-record query - full RFC 1035 support (name
        # compression, other record types, etc.) isn't needed here.
        transaction_id = os.getpid() & 0xFFFF
        header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        qname = b"".join(
            bytes([len(label)]) + label.encode("ascii")
            for label in hostname.split(".")
        ) + b"\x00"
        question = qname + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
        query = header + question

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (server, 53))
            response, _ = sock.recvfrom(512)

        if len(response) < 12 or response[0:2] != header[0:2]:
            return False, "malformed/mismatched response"
        rcode = response[3] & 0x0F
        answer_count = struct.unpack(">H", response[6:8])[0]
        if rcode != 0:
            return False, f"server returned error code {rcode}"
        if answer_count == 0:
            return False, "no answer records returned"
        return True, f"{answer_count} answer record(s)"
    except socket.timeout:
        return False, "query timed out (UDP/53 may be blocked)"
    except Exception as e:
        return False, f"query failed ({e})"


def check_dns_resolvers():
    """Query each resolver directly, bypassing the OS's configured DNS."""
    failures = {}
    for name, server in DNS_RESOLVERS.items():
        ok, detail = query_dns_server(server, EXTERNAL_HOST)
        if not ok:
            failures[name] = detail

    if not failures:
        return True, f"all resolvers OK ({', '.join(DNS_RESOLVERS)})"
    if len(failures) == len(DNS_RESOLVERS):
        return False, "all resolvers failed (UDP/53 likely blocked, or no network)"
    detail = "; ".join(f"{name}: {reason}" for name, reason in failures.items())
    return False, f"failed: {detail} (may indicate resolver-specific blocking)"


def traceroute(host, max_hops=15):
    """Run traceroute/tracert and return (stdout, stderr, returncode)."""
    if IS_WINDOWS:
        cmd = ["tracert", "-h", str(max_hops), "-w", "1000", host]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", "1", host]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=30,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", "command not found", None
    except subprocess.TimeoutExpired:
        return "", "timed out", None


def check_traceroute():
    out, err, _ = traceroute(EXTERNAL_HOST)
    hops = [line for line in out.splitlines() if line.strip() and line.strip()[0].isdigit()]
    if hops:
        star_only = [h for h in hops if "*" in h and not re.search(r"\d+\.\d+\.\d+\.\d+", h)]
        return True, f"{len(hops)} hops, {len(star_only)} unresponsive"

    # no hop lines usually means the command couldn't open a raw
    # socket (common in locked-down school/lab VMs) rather than an actual
    # network failure - surface that distinction instead of a bare FAIL.
    lowered = err.lower()
    if "not found" in lowered:
        return False, "traceroute/tracert not installed on this system"
    if "permitted" in lowered or "permission" in lowered or "privileg" in lowered:
        return False, "no permission for raw sockets (try running as admin/sudo)"
    if err.strip():
        return False, f"traceroute error: {err.strip().splitlines()[0]}"
    return False, "no hop data returned"


def check_ipv6():
    """
    Open a TCP connection over IPv6 directly, rather than shelling out to
    ping/ping6/ping -6 - those differ by OS and aren't guaranteed to be
    installed (some minimal Linux images drop iputils entirely), whereas
    an AF_INET6 socket connect is standard-library and identical on
    Windows, macOS, and Linux.
    """
    target = "2001:4860:4860::8888"  # Google Public DNS - stable, IPv6-only test target
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect((target, 53))
        return True, "IPv6 reachable (TCP connect succeeded)"
    except socket.gaierror:
        return False, "IPv6 not supported by this system's network stack"
    except OSError as e:
        return False, f"IPv6 unreachable ({e})"


def check_proxy_vpn():
    proxy_vars = [v for v in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
                  if os.environ.get(v)]
    if proxy_vars:
        return False, f"proxy env vars set: {', '.join(proxy_vars)} (may reroute traffic)"
    return True, "no proxy environment variables set"


def scan_ports(host, ports, timeout=1):
    open_ports = []
    for port, name in ports.items():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append((port, name))
        except OSError:
            continue
    return open_ports


def _report_open_ports(open_ports, where):
    if not open_ports:
        return True, f"no common ports open on {where}"
    insecure = [f"{p}/{n}" for p, n in open_ports if p in INSECURE_PORTS]
    all_ports = ", ".join(f"{p}/{n}" for p, n in open_ports)
    if insecure:
        # flag as a finding (not a hard FAIL) since some of
        # these are legitimate on a home LAN (e.g. SMB for file sharing) -
        # the point is to surface it for the student to evaluate, not to
        # assume it's malicious.
        return False, f"open: {all_ports} - insecure/high-risk: {', '.join(insecure)}"
    return True, f"open: {all_ports} (none flagged as high-risk)"


def check_local_ports():
    return _report_open_ports(scan_ports("127.0.0.1", COMMON_PORTS), "localhost")


def check_gateway_ports():
    gw = get_default_gateway()
    if not gw:
        return False, "could not determine default gateway"
    return _report_open_ports(scan_ports(gw, COMMON_PORTS), f"gateway {gw}")


def check_tls_integrity():
    """
    Fetch the certificate for HTTP_TEST_URL and verify it validates and
    matches the hostname. A validation failure here - on a well-known site
    that should have a perfectly good cert - is a strong signal of a
    TLS-intercepting proxy (school firewall, captive portal, or an
    on-path attacker performing a MITM).

    LIMITATION: this only catches interception where the intercepting
    proxy's certificate ISN'T trusted by the OS. A school- or
    company-installed root CA (common for content-filtering proxies) will
    still pass here, because it's trusted at the system level - this
    check can't distinguish that from a legitimate cert without comparing
    the issuer against a known-good fingerprint out of band.
    """
    host, port = HTTP_TEST_URL
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        return True, f"cert valid, issued by {issuer.get('organizationName', 'unknown')}"
    except ssl.SSLCertVerificationError as e:
        return False, f"certificate verification failed - possible MITM/interception ({e})"
    except Exception as e:
        return False, f"could not complete TLS handshake: {e}"


def get_arp_table():
    """
    Return raw ARP-cache text. `arp -a` works the same way on Windows,
    macOS, and most Linux, but some minimal Linux images ship only
    iproute2's `ip neighbor` (no legacy net-tools `arp`), so fall back to
    that - our regex-based parsing below just looks for an IP followed
    somewhere on the line by a MAC, which both formats satisfy.
    """
    commands = [["arp", "-a"]]
    if not IS_WINDOWS:
        commands.append(["ip", "neighbor"])
    for cmd in commands:
        try:
            out = subprocess.check_output(
                cmd, text=True, errors="ignore",
                stderr=subprocess.DEVNULL, timeout=5,
            )
            if out.strip():
                return out
        except Exception:
            continue
    return ""


def check_arp_spoofing():
    """
    Look for one MAC address claiming multiple IPs in the ARP cache. That's
    the classic signature of ARP spoofing (an attacker answering ARP
    requests for other hosts, e.g. the gateway, with their own MAC to
    intercept traffic). This is a heuristic, not proof - flag for review.
    """
    out = get_arp_table()
    if not out.strip():
        return False, "could not read ARP table"

    mac_pattern = r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
    pairs = re.findall(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+.*?(" + mac_pattern + ")", out)

    # exclude broadcast/multicast MACs - they're *supposed* to
    # answer for many IPs (every subnet's broadcast address, multicast
    # groups, etc.) so they'd otherwise trigger a guaranteed false positive
    # on every network.
    def is_broadcast_or_multicast(mac):
        mac = mac.lower().replace("-", ":")
        if mac == "ff:ff:ff:ff:ff:ff":
            return True
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x01)  # multicast bit (includes 01:00:5e IPv4 multicast)

    mac_to_ips = {}
    for ip, mac in pairs:
        if is_broadcast_or_multicast(mac):
            continue
        mac_to_ips.setdefault(mac.lower(), set()).add(ip)

    suspicious = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    if not pairs:
        return False, "no ARP entries found (or unrecognized arp -a format)"
    if suspicious:
        detail = "; ".join(f"{mac} -> {', '.join(ips)}" for mac, ips in suspicious.items())
        return False, f"one MAC answering for multiple IPs (possible ARP spoofing): {detail}"
    return True, f"{len(pairs)} ARP entries checked, no duplicate MACs found"


def main():
    global COLOR_ENABLED

    parser = argparse.ArgumentParser(description="Network diagnostic test suite")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable colored output",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="run only fast connectivity checks",
    )
    args = parser.parse_args()

    # also fall back to plain text when stdout isn't a real
    # terminal (e.g. piped to a file or `less`), since ANSI codes just show
    # up as garbage escape sequences in that case.
    COLOR_ENABLED = not args.no_color and sys.stdout.isatty()
    if COLOR_ENABLED and IS_WINDOWS:
        _enable_windows_ansi()

    print(colorize("Running network diagnostic test suite...", "bold") + "\n")

    connectivity_steps = [
        ("Local IP address", check_local_ip, CONNECTIVITY),
        ("Default gateway ping", check_gateway, CONNECTIVITY),
        ("External IP ping (bypasses DNS)", check_external_ip, CONNECTIVITY),
        ("DNS resolution", check_dns, CONNECTIVITY),
        ("TCP reachability (HTTPS)", lambda: check_tcp_port(*HTTP_TEST_URL), CONNECTIVITY),
        ("IPv6 reachability", check_ipv6, CONNECTIVITY),
    ]

    full_steps = [
        *connectivity_steps,

        # -- Performance: is the link slow or unstable --
        ("Traceroute to external host", check_traceroute, CONNECTIVITY),
        ("Packet loss/latency to gateway",
         lambda: check_packet_loss(get_default_gateway() or EXTERNAL_IP), PERFORMANCE),
        ("Packet loss/latency to external host",
         lambda: check_packet_loss(EXTERNAL_IP), PERFORMANCE),

        # -- Security: anything here worth a second look --
        ("DNS cross-check (multiple resolvers)", check_dns_resolvers, SECURITY),
        ("Proxy/VPN environment check", check_proxy_vpn, SECURITY),
        ("TLS certificate integrity", check_tls_integrity, SECURITY),
        ("ARP table spoofing check", check_arp_spoofing, SECURITY),
        ("Open ports on localhost", check_local_ports, SECURITY),
        ("Open ports on gateway", check_gateway_ports, SECURITY),
    ]

    steps = connectivity_steps if args.quick else full_steps

    results = run_all(steps)

    print()
    exit_ok = True
    for category, heading in [
        (CONNECTIVITY, "CONNECTIVITY"),
        (PERFORMANCE, "PERFORMANCE"),
        (SECURITY, "SECURITY"),
    ]:
        rows = [(label, ok, detail) for label, (cat, ok, detail) in results.items() if cat == category]
        failed = [label for label, ok, _ in rows if not ok]
        passed_count = len(rows) - len(failed)
        count_str = f"{passed_count}/{len(rows)} passed"
        count_str = colorize(count_str, "green") if not failed else colorize(count_str, "yellow")
        print(f"{colorize('==', 'cyan')} {colorize(heading, 'bold')}: {count_str} {colorize('==', 'cyan')}")
        for label in failed:
            print(f"  - {colorize(label, 'red')}")
        if failed:
            exit_ok = False
        print()

    print("Notes:")
    print("  - CONNECTIVITY failures usually point to where the link breaks:")
    print("    local IP -> gateway -> external IP -> DNS -> TCP/app layer,")
    print("    in that order.")
    print("  - PERFORMANCE failures (packet loss, high latency) suggest a")
    print("    slow/unstable link rather than a hard outage.")
    print("  - SECURITY findings are flags for you to evaluate, not automatic")
    print("    proof of compromise - e.g. an open SMB port may be intentional")
    print("    file sharing on a trusted home LAN.")

    sys.exit(0 if exit_ok else 1)


if __name__ == "__main__":
    main()