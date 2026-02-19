
# 🪷 Lotus
**Advanced Web Recon, JS Hunter & Sensitive File Grabber**

<p align="center">
  <img src="https://img.shields.io/badge/Author-0xmicho-f38ba8?style=flat-square" alt="Author">
  <img src="https://img.shields.io/badge/Bash-Script-4eba6a?style=flat-square" alt="Bash">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License">
</p>



### ⚠️ Legal Disclaimer
**Educational & Authorized Use Only!** This tool is created solely for security professionals, penetration testers, and bug bounty hunters. It is designed to be used ONLY on systems, networks, and applications that you have explicitly been authorized to test. 

The author (**0xmicho**) and contributors are not responsible for any illegal activity, misuse, or unauthorized use of this tool. By using this script, you agree that you are using it at your own risk and taking full responsibility for your actions.

---

### 📖 About Lotus
**Lotus** is a highly automated and intelligent bash script designed to streamline the reconnaissance phase of Bug Bounty hunting. It combines passive gathering and active crawling, followed by intelligent filtering to discover URLs, parameters, JavaScript files, and exposed sensitive/juicy endpoints. 

It also features an **On-Demand 403/401 Bypass module** to aggressively hunt for hidden directories using dozens of header injections and path normalization techniques.

### ✨ Key Features
- **Maximum Coverage Recon:** Combines multiple top-tier tools for both Passive and Active crawling.
- **Massive Sensitive File Hunting:** Uses an extensive, pre-configured list of extensions to find exposed backups, configs, database dumps, logs, and keys.
- **Juicy Endpoint Discovery:** Hunts for API endpoints, admin panels, swagger docs, and internal paths.
- **Advanced WAF/403 Bypass (Optional):** Tests over 100 bypass payloads (Headers & Path Tricks) to unlock forbidden access.
- **Smart Cleanup:** Automatically cleans and filters redundant URLs using `uro` to save your time.
- **Safe Execution:** Includes pre-flight dependency checks and clean exit handling (kills background jobs safely on `Ctrl+C`).

---

### 🛠️ Dependencies
Lotus relies on the power of the open-source community. You **MUST** have the following tools installed and accessible in your system's `$PATH`:

- [gauplus](https://github.com/bp0lr/gauplus)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [waymore](https://github.com/xnl-h4ck3r/waymore)
- [katana](https://github.com/projectdiscovery/katana)
- [gospider](https://github.com/jaeles-project/gospider)
- [hakrawler](https://github.com/hakluke/hakrawler)
- [httpx](https://github.com/projectdiscovery/httpx)
- [uro](https://github.com/s0md3v/uro)
- `curl` & `wget` (Standard Linux utilities)

---

### 🚀 Installation

```bash
# Clone the repository
git clone [https://github.com/0xmicho/Lotus.git](https://github.com/0xmicho/Lotus.git)

# Navigate to the directory
cd Lotus

# Make the script executable
chmod +x lotus.sh

```

### 💡 Usage

Lotus can take a single domain or a list of domains.

```bash
# Basic scan for a single domain
./lotus.sh domain.com

# Run with custom depth and threads
./lotus.sh -d 5 -t 30 domain.com

# Enable Katana Headless mode (Experimental)
./lotus.sh --headless domain.com

# Scan a list of domains from a file
./lotus.sh -l domains.txt

# Run the EXTREME 403/401 Bypass Module (Warning: Heavy & Slow!)
./lotus.sh --bypass domain.com

```

### 📝 Options

| Flag | Description | Default |
| --- | --- | --- |
| `-d` | Crawling depth | 3 |
| `-t` | Number of concurrent threads | 20 |
| `--headless` | Enable katana headless crawling | False |
| `--bypass` | Run heavy 403/401 bypass tests | False |
| `-l` | Input file containing list of domains | None |
| `-h` | Show help menu | None |

---

### 🗂️ Output Structure

All results are neatly organized inside a `lotus_result` directory, with a dedicated subfolder for each target domain containing:

* Cleaned URLs (`all_urls.txt`)
* Extracted parameters (`parameters.txt`)
* Live sensitive files & juicy paths
* Forbidden endpoints (and successful bypass logs if `--bypass` is used)
* Downloaded JavaScript files for manual analysis

---

### © Copyright & License

Created with ❤️ by **0xmicho**.

Released under the [MIT License](LICENSE).
