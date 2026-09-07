# Network Diagnostics Tool (`nt-tool`)

A simple terminal script to diagnose network issues. Checks for connection problems, poor speeds, and basic security risks using standard Python.

---

## What It Checks

* **Connectivity:** Tests your local IP, router connection, internet access, and DNS.
* **Performance:** Measures ping, packet loss, and runs a traceroute to spot network drops.
* **Security:** Looks for DNS blocking, TLS interception, ARP spoofing, and risky open ports.

---

## Requirements

* **Python 3.8+**
* Works on Windows, macOS, and Linux
* **No external packages needed**

---

## Setup & Usage

### Install:

```bash
git clone https://github.com/Terabase-Studios/nd_tool.git
cd nd_tool
pip install .

```
or
```bash
pip install nt-tool

```

### Run tests:

```bash
nt          # Full test suite
nt --quick  # Fast connection checks only

```

---

## License

[MIT](https://www.google.com/search?q=LICENSE)
