#!/bin/bash

# HexStrike AI - Tools Verification Script (V6 Complete Edition)
# Based on Official HexStrike-Ai V6 README - 200+ tools coverage
# Version 6.3 - Hardcoded Tools & UI Enhancements

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    FUTURISTIC COLOR & EFFECTS SYSTEM                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# Red Team Color Palette
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Pre-computed tool lists for performance
PIPX_INSTALLED_TOOLS=()
GEM_INSTALLED_TOOLS=()
PYTHON_INSTALLED_MODULES=()

# Initialize counters
INSTALLED_COUNT=0
MISSING_COUNT=0
TOTAL_COUNT=0

# Arrays to store tool information
ALL_TOOLS_STATUS=()

# Globals for UI Box
BOX_START_X=0
BOX_START_Y=0
BOX_WIDTH=0
BOX_HEIGHT=0
CONTENT_WIDTH=0
CONTENT_HEIGHT=0

# Hardcoded Tool Definitions
initialize_tools() {
    TOOLS["Network Reconnaissance & Scanning"]="Nmap|Rustscan|Masscan|AutoRecon|Amass|Subfinder|Fierce|DNSEnum|TheHarvester|ARP-Scan|NBTScan|RPCClient|Enum4linux|Enum4linux-ng|SMBMap|Responder|NetExec"
    TOOLS["Web Application Security Testing"]="Gobuster|Dirsearch|Feroxbuster|FFuf|Dirb|HTTPx|Katana|Hakrawler|Gau|Waybackurls|Nuclei|Nikto|SQLMap|WPScan|Arjun|ParamSpider|X8|Jaeles|Dalfox|Wafw00f|TestSSL|SSLScan|SSLyze|Anew|QSReplace|Uro|Whatweb|JWT-Tool|GraphQL-Voyager|Burp Suite Extensions|ZAP Proxy|Wfuzz|Commix|NoSQLMap|Tplmap"
    TOOLS["Authentication & Password Security"]="Hydra|John the Ripper|Hashcat|Medusa|Patator|NetExec|SMBMap|Evil-WinRM|Hash-Identifier|HashID|CrackStation|Ophcrack"
    TOOLS["Binary Analysis & Reverse Engineering"]="GDB|GDB-PEDA|GDB-GEF|Radare2|Ghidra|IDA Free|Binary Ninja|Binwalk|ROPgadget|Ropper|One-Gadget|Checksec|Strings|Objdump|Readelf|XXD|Hexdump|Pwntools|Angr|Libc-Database|Pwninit|Volatility|MSFVenom|UPX"
    TOOLS["Cloud & Container Security"]="Prowler|Scout Suite|CloudMapper|Pacu|Trivy|Clair|Kube-Hunter|Kube-Bench|Docker Bench Security|Falco|Checkov|Terrascan|CloudSploit|AWS CLI|Azure CLI|GCloud|Kubectl|Helm|Istio|OPA"
    TOOLS["CTF & Forensics Tools"]="Volatility|Volatility3|Foremost|PhotoRec|TestDisk|Steghide|Stegsolve|Zsteg|Outguess|ExifTool|Binwalk|Scalpel|Bulk Extractor|Autopsy|Sleuth Kit|John the Ripper|Hashcat|Hash-Identifier|CyberChef|Cipher-Identifier|Frequency-Analysis|RSATool|FactorDB"
    TOOLS["Bug Bounty & OSINT Arsenal"]="Amass|Subfinder|Hakrawler|HTTPx|ParamSpider|Aquatone|Subjack|DNSEnum|Fierce|TheHarvester|Sherlock|Social-Analyzer|Recon-ng|Maltego|SpiderFoot|Shodan|Censys|Have I Been Pwned|Pipl|TruffleHog"
}

# Centralized Tool Definitions
declare -A TOOLS

declare -A TOOL_LINKS
TOOL_LINKS=(
    ["Nmap"]="https://nmap.org/"
    ["Rustscan"]="https://github.com/RustScan/RustScan"
    ["Masscan"]="https://github.com/robertdavidgraham/masscan"
    ["AutoRecon"]="https://github.com/Tib3rius/AutoRecon"
    ["Amass"]="https://github.com/OWASP/Amass"
    ["Subfinder"]="https://github.com/projectdiscovery/subfinder"
    ["Fierce"]="https://github.com/mschwager/fierce"
    ["DNSEnum"]="https://github.com/fwaeytens/dnsenum"
    ["TheHarvester"]="https://github.com/laramies/theHarvester"
    ["ARP-Scan"]="https://github.com/royhills/arp-scan"
    ["NBTScan"]="https://github.com/resurrecting-open-source-projects/nbtscan"
    ["RPCClient"]="https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html"
    ["Enum4linux"]="https://github.com/CiscoCXSecurity/enum4linux"
    ["Enum4linux-ng"]="https://github.com/cddmp/enum4linux-ng"
    ["SMBMap"]="https://github.com/ShawnDEvans/smbmap"
    ["Responder"]="https://github.com/lgandx/Responder"
    ["NetExec"]="https://github.com/Pennyw0rth/NetExec"
    ["Gobuster"]="https://github.com/OJ/gobuster"
    ["Dirsearch"]="https://github.com/maurosoria/dirsearch"
    ["Feroxbuster"]="https://github.com/epi052/feroxbuster"
    ["FFuf"]="https://github.com/ffuf/ffuf"
    ["Dirb"]="https://www.kali.org/tools/dirb/"
    ["HTTPx"]="https://github.com/projectdiscovery/httpx"
    ["Katana"]="https://github.com/projectdiscovery/katana"
    ["Hakrawler"]="https://github.com/hakluke/hakrawler"
    ["Gau"]="https://github.com/lc/gau"
    ["Waybackurls"]="https://github.com/tomnomnom/waybackurls"
    ["Nuclei"]="https://github.com/projectdiscovery/nuclei"
    ["Nikto"]="https://github.com/sullo/nikto"
    ["SQLMap"]="https://sqlmap.org/"
    ["WPScan"]="https://wpscan.com/"
    ["Arjun"]="https://github.com/s0md3v/Arjun"
    ["ParamSpider"]="https://github.com/devanshbatham/ParamSpider"
    ["X8"]="https://github.com/Sh1Yo/x8"
    ["Jaeles"]="https://github.com/jaeles-project/jaeles"
    ["Dalfox"]="https://github.com/hahwul/dalfox"
    ["Wafw00f"]="https://github.com/EnableSecurity/wafw00f"
    ["TestSSL"]="https://github.com/drwetter/testssl.sh"
    ["SSLScan"]="https://github.com/rbsec/sslscan"
    ["SSLyze"]="https://github.com/nabla-c0d3/sslyze"
    ["Anew"]="https://github.com/tomnomnom/anew"
    ["QSReplace"]="https://github.com/tomnomnom/qsreplace"
    ["Uro"]="https://github.com/s0md3v/uro"
    ["Whatweb"]="https://github.com/urbanadventurer/WhatWeb"
    ["JWT-Tool"]="https://github.com/ticarpi/jwt_tool"
    ["GraphQL-Voyager"]="https://github.com/APIs-guru/graphql-voyager"
    ["Burp Suite Extensions"]="https://portswigger.net/burp/extender"
    ["ZAP Proxy"]="https://www.zaproxy.org/"
    ["Wfuzz"]="https://github.com/xmendez/wfuzz"
    ["Commix"]="https://github.com/commixproject/commix"
    ["NoSQLMap"]="https://github.com/codingo/NoSQLMap"
    ["Tplmap"]="https://github.com/epinna/tplmap"
    ["Hydra"]="https://github.com/vanhauser-thc/thc-hydra"
    ["John the Ripper"]="https://www.openwall.com/john/"
    ["Hashcat"]="https://hashcat.net/hashcat/"
    ["Medusa"]="https://github.com/jmk-foofus/medusa"
    ["Patator"]="https://github.com/lanjelot/patator"
    ["Evil-WinRM"]="https://github.com/Hackplayers/evil-winrm"
    ["Hash-Identifier"]="https://github.com/blackploit/hash-identifier"
    ["HashID"]="https://github.com/psypanda/hashID"
    ["CrackStation"]="https://crackstation.net/"
    ["Ophcrack"]="http://ophcrack.sourceforge.net/"
    ["GDB"]="https://www.gnu.org/software/gdb/"
    ["GDB-PEDA"]="https://github.com/longld/peda"
    ["GDB-GEF"]="https://github.com/hugsy/gef"
    ["Radare2"]="https://www.radare.org/n/radare2.html"
    ["Ghidra"]="https://ghidra-sre.org/"
    ["IDA Free"]="https://hex-rays.com/ida-free/"
    ["Binary Ninja"]="https://binary.ninja/"
    ["Binwalk"]="https://github.com/ReFirmLabs/binwalk"
    ["ROPgadget"]="https://github.com/JonathanSalwan/ROPgadget"
    ["Ropper"]="https://github.com/sashs/ropper"
    ["One-Gadget"]="https://github.com/david942j/one_gadget"
    ["Checksec"]="https://github.com/slimm609/checksec.sh"
    ["Strings"]="https://www.gnu.org/software/binutils/"
    ["Objdump"]="https://www.gnu.org/software/binutils/"
    ["Readelf"]="https://www.gnu.org/software/binutils/"
    ["XXD"]="https://www.vim.org/"
    ["Hexdump"]="https://github.com/util-linux/util-linux"
    ["Pwntools"]="https://github.com/Gallopsled/pwntools"
    ["Angr"]="https://angr.io/"
    ["Libc-Database"]="https://github.com/niklasb/libc-database"
    ["Pwninit"]="https://github.com/io12/pwninit"
    ["Volatility"]="https://www.volatilityfoundation.org/"
    ["MSFVenom"]="https://www.metasploit.com/"
    ["UPX"]="https://upx.github.io/"
    ["Prowler"]="https://github.com/prowler-cloud/prowler"
    ["Scout Suite"]="https://github.com/nccgroup/ScoutSuite"
    ["CloudMapper"]="https://github.com/duo-labs/cloudmapper"
    ["Pacu"]="https://github.com/RhinoSecurityLabs/pacu"
    ["Trivy"]="https://github.com/aquasecurity/trivy"
    ["Clair"]="https://github.com/quay/clair"
    ["Kube-Hunter"]="https://github.com/aquasecurity/kube-hunter"
    ["Kube-Bench"]="https://github.com/aquasecurity/kube-bench"
    ["Docker Bench Security"]="https://github.com/docker/docker-bench-security"
    ["Falco"]="https://falco.org/"
    ["Checkov"]="https://www.checkov.io/"
    ["Terrascan"]="https://github.com/tenable/terrascan"
    ["CloudSploit"]="https://github.com/aquasecurity/cloudsploit"
    ["AWS CLI"]="https://aws.amazon.com/cli/"
    ["Azure CLI"]="https://docs.microsoft.com/en-us/cli/azure/"
    ["GCloud"]="https://cloud.google.com/sdk/gcloud"
    ["Kubectl"]="https://kubernetes.io/docs/reference/kubectl/overview/"
    ["Helm"]="https://helm.sh/"
    ["Istio"]="https://istio.io/"
    ["OPA"]="https://www.openpolicyagent.org/"
    ["Volatility3"]="https://github.com/volatilityfoundation/volatility3"
    ["Foremost"]="http://foremost.sourceforge.net/"
    ["PhotoRec"]="https://www.cgsecurity.org/wiki/PhotoRec"
    ["TestDisk"]="https://www.cgsecurity.org/wiki/TestDisk"
    ["Steghide"]="http://steghide.sourceforge.net/"
    ["Stegsolve"]="https://github.com/zardus/stegsolve"
    ["Zsteg"]="https://github.com/zed-0xff/zsteg"
    ["Outguess"]="https://github.com/resurrecting-open-source-projects/outguess"
    ["ExifTool"]="https://exiftool.org/"
    ["Scalpel"]="https://github.com/sleuthkit/scalpel"
    ["Bulk Extractor"]="https://github.com/simsong/bulk_extractor"
    ["Autopsy"]="https://www.sleuthkit.org/autopsy/"
    ["Sleuth Kit"]="https://www.sleuthkit.org/"
    ["CyberChef"]="https://gchq.github.io/CyberChef/"
    ["Cipher-Identifier"]="https://github.com/blackploit/cipher-identifier"
    ["Frequency-Analysis"]="https://www.dcode.fr/frequency-analysis"
    ["RSATool"]="https://github.com/R-s-s/RSATool"
    ["FactorDB"]="http://factordb.com/"
    ["Sherlock"]="https://github.com/sherlock-project/sherlock"
    ["Social-Analyzer"]="https://github.com/qeeqbox/social-analyzer"
    ["Recon-ng"]="https://github.com/lanmaster53/recon-ng"
    ["Maltego"]="https://www.maltego.com/"
    ["SpiderFoot"]="https://www.spiderfoot.net/"
    ["Shodan"]="https://www.shodan.io/"
    ["Censys"]="https://censys.io/"
    ["Have I Been Pwned"]="https://haveibeenpwned.com/"
    ["Pipl"]="https://pipl.com/"
    ["TruffleHog"]="https://github.com/trufflesecurity/truffleHog"
)

declare -A TOOL_EXECUTABLES
TOOL_EXECUTABLES=(
    ["Nmap"]="nmap"
    ["Rustscan"]="rustscan"
    ["Masscan"]="masscan"
    ["AutoRecon"]="autorecon"
    ["Amass"]="amass"
    ["Subfinder"]="subfinder"
    ["Fierce"]="fierce"
    ["DNSEnum"]="dnsenum"
    ["TheHarvester"]="theharvester"
    ["ARP-Scan"]="arp-scan"
    ["NBTScan"]="nbtscan"
    ["RPCClient"]="rpcclient"
    ["Enum4linux"]="enum4linux"
    ["Enum4linux-ng"]="enum4linux-ng"
    ["SMBMap"]="smbmap"
    ["Responder"]="responder"
    ["NetExec"]="netexec"
    ["Gobuster"]="gobuster"
    ["Dirsearch"]="dirsearch"
    ["Feroxbuster"]="feroxbuster"
    ["FFuf"]="ffuf"
    ["Dirb"]="dirb"
    ["HTTPx"]="httpx"
    ["Katana"]="katana"
    ["Hakrawler"]="hakrawler"
    ["Gau"]="gau"
    ["Waybackurls"]="waybackurls"
    ["Nuclei"]="nuclei"
    ["Nikto"]="nikto"
    ["SQLMap"]="sqlmap"
    ["WPScan"]="wpscan"
    ["Arjun"]="arjun"
    ["ParamSpider"]="paramspider"
    ["X8"]="x8"
    ["Jaeles"]="jaeles"
    ["Dalfox"]="dalfox"
    ["Wafw00f"]="wafw00f"
    ["TestSSL"]="testssl.sh"
    ["SSLScan"]="sslscan"
    ["SSLyze"]="sslyze"
    ["Anew"]="anew"
    ["QSReplace"]="qsreplace"
    ["Uro"]="uro"
    ["Whatweb"]="whatweb"
    ["JWT-Tool"]="jwt_tool"
    ["ZAP Proxy"]="zaproxy"
    ["Wfuzz"]="wfuzz"
    ["Commix"]="commix"
    ["NoSQLMap"]="nosqlmap"
    ["Tplmap"]="tplmap"
    ["Hydra"]="hydra"
    ["John the Ripper"]="john"
    ["Hashcat"]="hashcat"
    ["Medusa"]="medusa"
    ["Patator"]="patator"
    ["Evil-WinRM"]="evil-winrm"
    ["Hash-Identifier"]="hash-identifier"
    ["HashID"]="hashid"
    ["Ophcrack"]="ophcrack"
    ["GDB"]="gdb"
    ["Radare2"]="radare2"
    ["Ghidra"]="ghidra"
    ["Binwalk"]="binwalk"
    ["ROPgadget"]="ROPgadget.py"
    ["Ropper"]="ropper"
    ["One-Gadget"]="one_gadget"
    ["Checksec"]="checksec"
    ["Strings"]="strings"
    ["Objdump"]="objdump"
    ["Readelf"]="readelf"
    ["XXD"]="xxd"
    ["Hexdump"]="hexdump"
    ["Pwntools"]="pwn"
    ["Angr"]="angr"
    ["Pwninit"]="pwninit"
    ["Volatility"]="vol.py"
    ["MSFVenom"]="msfvenom"
    ["UPX"]="upx"
    ["Prowler"]="prowler"
    ["Trivy"]="trivy"
    ["Kube-Hunter"]="kube-hunter"
    ["Kube-Bench"]="kube-bench"
    ["Checkov"]="checkov"
    ["AWS CLI"]="aws"
    ["Azure CLI"]="az"
    ["GCloud"]="gcloud"
    ["Kubectl"]="kubectl"
    ["Helm"]="helm"
    ["Istio"]="istioctl"
    ["OPA"]="opa"
    ["Volatility3"]="vol"
    ["Foremost"]="foremost"
    ["PhotoRec"]="photorec"
    ["TestDisk"]="testdisk"
    ["Steghide"]="steghide"
    ["Zsteg"]="zsteg"
    ["Outguess"]="outguess"
    ["ExifTool"]="exiftool"
    ["Scalpel"]="scalpel"
    ["Bulk Extractor"]="bulk_extractor"
    ["Autopsy"]="autopsy"
    ["RSATool"]="rsatool"
    ["FactorDB"]="factordb-cli"
    ["Sherlock"]="sherlock"
    ["Social-Analyzer"]="social-analyzer"
    ["Recon-ng"]="recon-ng"
    ["Maltego"]="maltego"
    ["SpiderFoot"]="spiderfoot"
    ["Shodan"]="shodan"
    ["Censys"]="censys"
    ["Have I Been Pwned"]="pwned"
    ["TruffleHog"]="trufflehog"
)

declare -A TOOL_COMMANDS
TOOL_COMMANDS=(
    ["Nmap"]="sudo apt install nmap"
    ["Rustscan"]="sudo apt install rustscan"
    ["Masscan"]="sudo apt install masscan"
    ["AutoRecon"]="pipx install git+https://github.com/Tib3rius/AutoRecon.git"
    ["Amass"]="sudo apt install amass"
    ["Subfinder"]="sudo apt install subfinder"
    ["Fierce"]="sudo apt install fierce"
    ["DNSEnum"]="sudo apt install dnsenum"
    ["TheHarvester"]="sudo apt install theharvester"
    ["ARP-Scan"]="sudo apt install arp-scan"
    ["NBTScan"]="sudo apt install nbtscan"
    ["RPCClient"]="sudo apt install smbclient"
    ["Enum4linux"]="sudo apt install enum4linux"
    ["Enum4linux-ng"]="pipx install enum4linux-ng"
    ["SMBMap"]="pipx install smbmap"
    ["Responder"]="sudo apt install responder"
    ["NetExec"]="pipx install netexec"
    ["Gobuster"]="sudo apt install gobuster"
    ["Dirsearch"]="sudo apt install dirsearch"
    ["Feroxbuster"]="sudo apt install feroxbuster"
    ["FFuf"]="sudo apt install ffuf"
    ["Dirb"]="sudo apt install dirb"
    ["HTTPx"]="sudo apt install httpx-toolkit"
    ["Katana"]="sudo apt install katana"
    ["Hakrawler"]="go install github.com/hakluke/hakrawler@latest"
    ["Gau"]="go install github.com/lc/gau/v2/cmd/gau@latest"
    ["Waybackurls"]="go install github.com/tomnomnom/waybackurls@latest"
    ["Nuclei"]="sudo apt install nuclei"
    ["Nikto"]="sudo apt install nikto"
    ["SQLMap"]="sudo apt install sqlmap"
    ["WPScan"]="sudo apt install wpscan"
    ["Arjun"]="sudo apt install arjun"
    ["ParamSpider"]="pipx install paramspider"
    ["X8"]="N/A"
    ["Jaeles"]="go install github.com/jaeles-project/jaeles@latest"
    ["Dalfox"]="sudo apt install dalfox"
    ["Wafw00f"]="sudo apt install wafw00f"
    ["TestSSL"]="sudo apt install testssl.sh"
    ["SSLScan"]="sudo apt install sslscan"
    ["SSLyze"]="pipx install sslyze"
    ["Anew"]="go install github.com/tomnomnom/anew@latest"
    ["QSReplace"]="go install github.com/tomnomnom/qsreplace@latest"
    ["Uro"]="pipx install uro"
    ["Whatweb"]="sudo apt install whatweb"
    ["JWT-Tool"]="pipx install jwt_tool"
    ["GraphQL-Voyager"]="N/A"
    ["Burp Suite Extensions"]="N/A"
    ["ZAP Proxy"]="sudo apt install zaproxy"
    ["Wfuzz"]="pipx install wfuzz"
    ["Commix"]="pipx install commix"
    ["NoSQLMap"]="pipx install nosqlmap"
    ["Tplmap"]="pipx install tplmap"
    ["Hydra"]="sudo apt install hydra"
    ["John the Ripper"]="sudo apt install john"
    ["Hashcat"]="sudo apt install hashcat"
    ["Medusa"]="sudo apt install medusa"
    ["Patator"]="sudo apt install patator"
    ["Evil-WinRM"]="gem install evil-winrm"
    ["Hash-Identifier"]="sudo apt install hash-identifier"
    ["HashID"]="pipx install hashid"
    ["CrackStation"]="N/A"
    ["Ophcrack"]="sudo apt install ophcrack"
    ["GDB"]="sudo apt install gdb"
    ["GDB-PEDA"]="N/A"
    ["GDB-GEF"]="N/A"
    ["Radare2"]="sudo apt install radare2"
    ["Ghidra"]="sudo apt install ghidra"
    ["IDA Free"]="N/A"
    ["Binary Ninja"]="N/A"
    ["Binwalk"]="sudo apt install binwalk"
    ["ROPgadget"]="pipx install ropgadget"
    ["Ropper"]="pipx install ropper"
    ["One-Gadget"]="gem install one_gadget"
    ["Checksec"]="sudo apt install checksec"
    ["Strings"]="sudo apt install binutils"
    ["Objdump"]="sudo apt install binutils"
    ["Readelf"]="sudo apt install binutils"
    ["XXD"]="sudo apt install xxd"
    ["Hexdump"]="sudo apt install bsdmainutils"
    ["Pwntools"]="pipx install pwntools"
    ["Angr"]="pipx install angr"
    ["Libc-Database"]="N/A"
    ["Pwninit"]="pipx install pwninit"
    ["Volatility"]="pipx install volatility"
    ["MSFVenom"]="sudo apt install metasploit-framework"
    ["UPX"]="sudo apt install upx-ucl"
    ["Prowler"]="pipx install prowler"
    ["Scout Suite"]="pipx install scout-suite"
    ["CloudMapper"]="pipx install cloudmapper"
    ["Pacu"]="pipx install pacu"
    ["Trivy"]="sudo apt install trivy"
    ["Clair"]="N/A"
    ["Kube-Hunter"]="pipx install kube-hunter"
    ["Kube-Bench"]="sudo apt install kube-bench"
    ["Docker Bench Security"]="N/A"
    ["Falco"]="N/A"
    ["Checkov"]="pipx install checkov"
    ["Terrascan"]="N/A"
    ["CloudSploit"]="N/A"
    ["AWS CLI"]="sudo apt install awscli"
    ["Azure CLI"]="pipx install azure-cli"
    ["GCloud"]="N/A"
    ["Kubectl"]="sudo apt install kubectl"
    ["Helm"]="sudo apt install helm"
    ["Istio"]="N/A"
    ["OPA"]="N/A"
    ["Volatility3"]="pipx install volatility3"
    ["Foremost"]="sudo apt install foremost"
    ["PhotoRec"]="sudo apt install testdisk"
    ["TestDisk"]="sudo apt install testdisk"
    ["Steghide"]="sudo apt install steghide"
    ["Stegsolve"]="N/A"
    ["Zsteg"]="gem install zsteg"
    ["Outguess"]="sudo apt install outguess"
    ["ExifTool"]="sudo apt install libimage-exiftool-perl"
    ["Scalpel"]="sudo apt install scalpel"
    ["Bulk Extractor"]="sudo apt install bulk-extractor"
    ["Autopsy"]="sudo apt install autopsy"
    ["Sleuth Kit"]="sudo apt install sleuthkit"
    ["CyberChef"]="N/A"
    ["Cipher-Identifier"]="N/A"
    ["Frequency-Analysis"]="N/A"
    ["RSATool"]="pipx install rsatool"
    ["FactorDB"]="pipx install factordb"
    ["Sherlock"]="pipx install sherlock-project"
    ["Social-Analyzer"]="pipx install social-analyzer"
    ["Recon-ng"]="pipx install recon-ng"
    ["Maltego"]="sudo apt install maltego"
    ["SpiderFoot"]="pipx install spiderfoot"
    ["Shodan"]="pipx install shodan"
    ["Censys"]="pipx install censys"
    ["Have I Been Pwned"]="pipx install haveibeenpwned"
    ["Pipl"]="N/A"
    ["TruffleHog"]="pipx install trufflehog"
)

# Helper to move cursor to a given location inside the box
cur_mov() {
    printf "\033[$((${BOX_START_Y} + $1));$((${BOX_START_X} + $2))H"
}

# Function to draw the main UI box
draw_box() {
    BOX_WIDTH=$(tput cols)
    BOX_HEIGHT=$(tput lines)
    CONTENT_WIDTH=$((BOX_WIDTH - 4))
    CONTENT_HEIGHT=$((BOX_HEIGHT - 2))
    # Use 1-based indexing for cursor positioning.
    BOX_START_X=1
    BOX_START_Y=1
    
    printf "\033[2J\033[?25l"

    cur_mov 0 0
    printf "${BLUE}╔"
    for ((i=1; i<BOX_WIDTH-1; i++)); do printf "═"; done
    printf "╗"

    for ((i=1; i<BOX_HEIGHT-1; i++)); do
        cur_mov $i 0; printf "║"
        cur_mov $i $((BOX_WIDTH-1)); printf "║"
    done

    cur_mov $((BOX_HEIGHT-1)) 0
    printf "╚"
    for ((i=1; i<BOX_WIDTH-1; i++)); do printf "═"; done
    printf "╝${NC}"
}

# Optimized tool checking function
check_tool() {
    local descriptive_name=$1
    local category=${2:-"General"}
    local status="MISSING"

    local executable_to_check=${TOOL_EXECUTABLES[$descriptive_name]}
    local check_names=()
    if [ -n "$executable_to_check" ]; then
        check_names+=("$executable_to_check")
    else
        check_names+=("$descriptive_name" "${descriptive_name,,}")
    fi

    for name in "${check_names[@]}"; do
        if command -v "$name" &> /dev/null || \
           [ -f "$HOME/go/bin/$name" ] || \
           [[ " ${PIPX_INSTALLED_TOOLS[*]} " =~ " ${name} " ]] || \
           [[ " ${GEM_INSTALLED_TOOLS[*]} " =~ " ${name} " ]] || \
           [[ " ${PYTHON_INSTALLED_MODULES[*]} " =~ " ${name//-/_} " ]]; then
            status="INSTALLED"
            break
        fi
    done

    if [ "$status" == "INSTALLED" ]; then
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    else
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi

    ALL_TOOLS_STATUS+=("$category,$descriptive_name,$status")
}

precompute_installed_tools() {
    # Get all pipx tools at once
    mapfile -t PIPX_INSTALLED_TOOLS < <(pipx list --short 2>/dev/null)
    # Get all gem tools at once
    mapfile -t GEM_INSTALLED_TOOLS < <(gem list --no-versions 2>/dev/null)

    # Generate a python script to check all modules at once
    local python_modules_to_check=()
    for descriptive_name in "${!TOOL_EXECUTABLES[@]}"; do
        local executable_name=${TOOL_EXECUTABLES[$descriptive_name]}
        # A simple heuristic: if it's not a clear command, it might be a python module
        if ! command -v "$executable_name" &>/dev/null && ! [[ "$executable_name" =~ (\.sh|\.py)$ ]]; then
             python_modules_to_check+=("${executable_name//-/_}")
        fi
    done

    # Create and run a python script to check for module existence
    local check_script_path="/tmp/check_modules.py"
    cat > "$check_script_path" <<- EOM
import importlib.util, sys
found_modules = [m for m in sys.argv[1:] if importlib.util.find_spec(m)]
print(" ".join(found_modules))
EOM

    if (( ${#python_modules_to_check[@]} > 0 )); then
        local found_py_modules
        found_py_modules=$(python3 "$check_script_path" "${python_modules_to_check[@]}")
        PYTHON_INSTALLED_MODULES=($found_py_modules)
    fi
    rm "$check_script_path"
}


run_all_checks() {
    local content_y=7
    local i=0
    local progress_bar_width=50

    local sorted_categories=()
    mapfile -t sorted_categories < <(printf "%s\n" "${!TOOLS[@]}" | sort)

    for category in "${sorted_categories[@]}"; do
        local IFS='|'
        local tool_list=(${TOOLS[$category]})
        local num_tools_in_cat=${#tool_list[@]}

        local cat_scan_msg="Scanning Category: ${PURPLE}${category}${NC} ($num_tools_in_cat tools)"
        cur_mov $content_y 3
        printf "%-s" "$cat_scan_msg"
        printf "%*s" $((CONTENT_WIDTH - ${#cat_scan_msg} + 15)) ""

        for tool in "${tool_list[@]}"; do
            check_tool "$tool" "$category"
            i=$((i+1))

            local progress=$((i * 100 / TOTAL_COUNT))
            local filled_width=$((progress * progress_bar_width / 100))

            cur_mov $((content_y + 1)) 3
            printf "${WHITE}Overall Progress: ${CYAN}["
            for ((j=0; j<filled_width; j++)); do printf "▉"; done
            for ((j=filled_width; j<progress_bar_width; j++)); do printf " "; done
            printf "] %d%% (%d/%d)${NC}" "$progress" "$i" "$TOTAL_COUNT"
        done
    done

    # Clear the scanning lines
    cur_mov $content_y 3; printf "%*s" $CONTENT_WIDTH ""
    cur_mov $((content_y + 1)) 3; printf "%*s" $CONTENT_WIDTH ""
}

calculate_total_tools() {
    TOTAL_COUNT=0
    for category in "${!TOOLS[@]}"; do
        local IFS='|'
        local tool_array=(${TOOLS[$category]})
        TOTAL_COUNT=$((TOTAL_COUNT + ${#tool_array[@]}))
    done
}

show_logo() {
    local logo_y=1
    local logo_x=$(( (CONTENT_WIDTH - 50) / 2 ))
    
    cur_mov $((logo_y++)) $((logo_x)); printf "${RED} __   __   ___   __   _   _   ___   __   __  ${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${RED}|  | |  | | __| |  \\ | | | | | __| |  \\ |  | ${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${RED}|  | |  | | __| | D | | | | | __| | D | |  | ${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${RED}|_\\_/\\_/  |___| |__/  |_| |_| |___| |__/  |__| ${NC}"
    
    logo_y=$((logo_y + 1))
    cur_mov $((logo_y)) 2
    printf "${RED}"
    for ((i=0; i<CONTENT_WIDTH; i++)); do printf "─"; done
    printf "${NC}"
}

# Main function
main() {
    trap 'printf "\033[?25h"' EXIT
    initialize_tools
    calculate_total_tools
    precompute_installed_tools

    draw_box
    show_logo

    run_all_checks

    local content_y=7
    show_report "$content_y"
    
    printf "\033[?25h"
}

show_report() {
    local content_y=$1
    local display_start_index=0
    
    # --- Pager Loop ---
    while true; do
        # Clear the report area for redraw
        for ((i=content_y; i < BOX_HEIGHT - 2; i++)); do
            cur_mov $i 2
            printf "%*s" $CONTENT_WIDTH ""
        done

        local current_y=$content_y

        # --- Summary Header ---
        local summary_line
        summary_line=$(printf "${WHITE}Scan Summary: ${GREEN}%d Installed${WHITE}, ${RED}%d Missing${WHITE}, ${CYAN}%d Total${NC}" \
                              "$INSTALLED_COUNT" "$MISSING_COUNT" "$TOTAL_COUNT")
        local summary_x=$(( (CONTENT_WIDTH - ${#summary_line} + 19) / 2 )) # +19 for color codes
        cur_mov $current_y $summary_x
        echo -e "$summary_line"
        current_y=$((current_y + 2))

        # --- Single-Column Layout ---
        local report_body_height=$((BOX_HEIGHT - content_y - 5))
        local max_visible_items=$report_body_height

        # --- Display Page of Tools ---
        local items_to_display=("${ALL_TOOLS_STATUS[@]:display_start_index:max_visible_items}")
        
        for tool_status in "${items_to_display[@]}"; do
            IFS=',' read -r category tool status <<< "$tool_status"

            cur_mov $current_y 3

            if [ "$status" == "INSTALLED" ]; then
                printf "${GREEN}[✓] %-20s ${PURPLE}(%s)${NC}" "$tool" "$category"
            else
                local install_cmd=${TOOL_COMMANDS[$tool]:-"N/A"}
                printf "${RED}[✗] %-20s ${PURPLE}(%s) - ${YELLOW}%s${NC}" "$tool" "$category" "$install_cmd"
            fi
            current_y=$((current_y + 1))
        done
        
        # --- Footer ---
        local footer_y=$((BOX_HEIGHT - 2))
        cur_mov $footer_y 2
        printf "${RED}"
        for ((i=0; i<CONTENT_WIDTH; i++)); do printf "─"; done
        printf "${NC}"

        local footer_text_y=$((BOX_HEIGHT - 1))
        cur_mov $footer_text_y 3
        printf "${CYAN}Ethical Warning: Use these tools responsibly and only on systems you are authorized to test. Created By 'PureHate'${NC}"

        # --- Pager instructions ---
        local pager_y=$((BOX_HEIGHT - 3))
        cur_mov $pager_y 3
        if (( ${#ALL_TOOLS_STATUS[@]} > max_visible_items )); then
            printf "${WHITE}Use [w/s] to scroll, [q] to quit. Page %d/%d${NC}" \
                   $((display_start_index / max_visible_items + 1)) \
                   $(( (${#ALL_TOOLS_STATUS[@]} + max_visible_items - 1) / max_visible_items ))
        else
             printf "${WHITE}Press [q] to quit.${NC}"
        fi

        # --- Wait for user input ---
        if [ -t 0 ]; then # Check if stdin is a terminal
            read -rsn1 key
        else # Not in a tty, so don't wait for input
            break
        fi
        case "$key" in
            q) break ;;
            w) display_start_index=$((display_start_index - max_visible_items))
               if (( display_start_index < 0 )); then display_start_index=0; fi
               ;;
            s) display_start_index=$((display_start_index + max_visible_items))
               local max_index=$((${#ALL_TOOLS_STATUS[@]} - max_visible_items))
               if (( display_start_index > max_index )); then display_start_index=$max_index; fi
               if (( display_start_index < 0 )); then display_start_index=0; fi # handle case where there's less than one page
               ;;
        esac
    done
}


main