#!/bin/bash

# HexStrike AI - Official Tools Verification Script (Based on Official README)
# Supports multiple Linux distributions with verified download links
# Version 4.0 - Complete coverage of all 150+ HexStrike AI tools

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
ORANGE='\033[0;33m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Enhanced Banner
echo -e "${CYAN}"
echo "██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗"
echo "██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝"
echo "███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  "
echo "██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  "
echo "██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗"
echo "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${WHITE}${BOLD}HexStrike AI - Official Security Tools Checker v4.0${NC}"
echo -e "${BLUE}🔗 Based on official HexStrike AI README - 150+ tools coverage${NC}"
echo -e "${ORANGE}📋 Comprehensive verification with working download links${NC}"
echo -e "${PURPLE}🚀 Enhanced with advanced exploitation and mobile security tools${NC}"
echo ""

# Check if curl is available for link validation
CURL_AVAILABLE=false
if command -v curl > /dev/null 2>&1; then
    CURL_AVAILABLE=true
fi

# Function to check if URL is accessible
check_url() {
    local url=$1
    if [ "$CURL_AVAILABLE" = true ]; then
        if curl --output /dev/null --silent --head --fail --max-time 10 "$url"; then
            return 0
        else
            return 1
        fi
    else
        return 0  # Assume working if curl not available
    fi
}

# Detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        PRETTY_NAME="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        PRETTY_NAME=$(cat /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        PRETTY_NAME="Debian $(cat /etc/debian_version)"
    else
        DISTRO="unknown"
        PRETTY_NAME="Unknown Linux Distribution"
    fi
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_TYPE="amd64" ;;
        aarch64|arm64) ARCH_TYPE="arm64" ;;
        armv7l) ARCH_TYPE="armv7" ;;
        i686|i386) ARCH_TYPE="i386" ;;
        *) ARCH_TYPE="amd64" ;;
    esac
    
    echo -e "${BLUE}🐧 Detected OS: ${CYAN}$PRETTY_NAME${NC}"
    echo -e "${BLUE}📋 Distribution: ${CYAN}$DISTRO${NC}"
    echo -e "${BLUE}🏗️  Architecture: ${CYAN}$ARCH ($ARCH_TYPE)${NC}"
    echo ""
}

# Get package manager and install commands based on distro
get_package_manager() {
    case $DISTRO in
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            PKG_MANAGER="apt"
            INSTALL_CMD="sudo apt update && sudo apt install -y"
            UPDATE_CMD="sudo apt update"
            ;;
        "fedora"|"rhel"|"centos")
            if command -v dnf > /dev/null 2>&1; then
                PKG_MANAGER="dnf"
                INSTALL_CMD="sudo dnf install -y"
                UPDATE_CMD="sudo dnf update"
            else
                PKG_MANAGER="yum"
                INSTALL_CMD="sudo yum install -y"
                UPDATE_CMD="sudo yum update"
            fi
            ;;
        "arch"|"manjaro"|"endeavouros")
            PKG_MANAGER="pacman"
            INSTALL_CMD="sudo pacman -S"
            UPDATE_CMD="sudo pacman -Syu"
            ;;
        "opensuse"|"opensuse-leap"|"opensuse-tumbleweed")
            PKG_MANAGER="zypper"
            INSTALL_CMD="sudo zypper install -y"
            UPDATE_CMD="sudo zypper update"
            ;;
        "alpine")
            PKG_MANAGER="apk"
            INSTALL_CMD="sudo apk add"
            UPDATE_CMD="sudo apk update"
            ;;
        *)
            PKG_MANAGER="unknown"
            INSTALL_CMD="# Unknown package manager - manual installation required"
            UPDATE_CMD="# Unknown package manager"
            ;;
    esac
    
    echo -e "${BLUE}📦 Package Manager: ${CYAN}$PKG_MANAGER${NC}"
    echo ""
}

# Initialize counters
INSTALLED_COUNT=0
MISSING_COUNT=0
TOTAL_COUNT=0

# Arrays to store results
INSTALLED_TOOLS=()
MISSING_TOOLS=()

# Complete tool installation database - EXPANDED TO 150+ TOOLS
declare -A TOOL_INSTALL_INFO
init_complete_tool_database() {
    # 🔍 Network Reconnaissance & Scanning (EXPANDED)
    TOOL_INSTALL_INFO["nmap"]="pkg_manager|nmap|Advanced port scanning with custom NSE scripts"
    TOOL_INSTALL_INFO["amass"]="go_install|github.com/owasp-amass/amass/v4/cmd/amass|Comprehensive subdomain enumeration and OSINT"
    TOOL_INSTALL_INFO["subfinder"]="go_install|github.com/projectdiscovery/subfinder/v2/cmd/subfinder|Fast passive subdomain discovery"
    TOOL_INSTALL_INFO["nuclei"]="go_install|github.com/projectdiscovery/nuclei/v3/cmd/nuclei|Fast vulnerability scanner with 4000+ templates"
    TOOL_INSTALL_INFO["autorecon"]="pip_install|autorecon|Automated reconnaissance with 35+ parameters"
    TOOL_INSTALL_INFO["fierce"]="pip_install|fierce|DNS reconnaissance and zone transfer testing"
    TOOL_INSTALL_INFO["masscan"]="pkg_manager|masscan|High-speed Internet-scale port scanner"
    TOOL_INSTALL_INFO["theharvester"]="pkg_manager|theharvester|Email/subdomain harvester"
    TOOL_INSTALL_INFO["responder"]="pkg_manager|responder|LLMNR/NBT-NS/MDNS poisoner"
    TOOL_INSTALL_INFO["netexec"]="pip_install|netexec|Network service exploitation tool"
    TOOL_INSTALL_INFO["enum4linux-ng"]="github_manual|https://github.com/cddmp/enum4linux-ng|Next-generation enum4linux"
    TOOL_INSTALL_INFO["dnsenum"]="pkg_manager|dnsenum|DNS enumeration script"
    TOOL_INSTALL_INFO["rustscan"]="github_release|https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.1.1_amd64.deb|Ultra-fast port scanner"
    TOOL_INSTALL_INFO["shodan"]="pip_install|shodan|Shodan search engine CLI"
    TOOL_INSTALL_INFO["censys"]="pip_install|censys|Censys internet search platform"
    TOOL_INSTALL_INFO["naabu"]="go_install|github.com/projectdiscovery/naabu/v2/cmd/naabu|Fast port scanner with SYN/CONNECT/UDP scanning"
    TOOL_INSTALL_INFO["httpx"]="go_install|github.com/projectdiscovery/httpx/cmd/httpx|Fast and multi-purpose HTTP toolkit"
    TOOL_INSTALL_INFO["alive"]="go_install|github.com/projectdiscovery/asnmap/cmd/asnmap|ASN mapping tool"
    TOOL_INSTALL_INFO["uncover"]="go_install|github.com/projectdiscovery/uncover/cmd/uncover|Search engine discovery"
    TOOL_INSTALL_INFO["mapcidr"]="go_install|github.com/projectdiscovery/mapcidr/cmd/mapcidr|CIDR manipulation utility"
    TOOL_INSTALL_INFO["chaos"]="go_install|github.com/projectdiscovery/chaos-client/cmd/chaos|Passive DNS replication"
    TOOL_INSTALL_INFO["dnsx"]="go_install|github.com/projectdiscovery/dnsx/cmd/dnsx|DNS toolkit"
    TOOL_INSTALL_INFO["shuffledns"]="go_install|github.com/projectdiscovery/shuffledns/cmd/shuffledns|Wrapper for MassDNS"
    TOOL_INSTALL_INFO["assetfinder"]="go_install|github.com/tomnomnom/assetfinder|Asset discovery tool"
    TOOL_INSTALL_INFO["findomain"]="github_release|https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux|Fast subdomain enumerator"
    TOOL_INSTALL_INFO["crtsh"]="github_manual|https://github.com/cemulus/crtsh|Certificate transparency logs searcher"
    TOOL_INSTALL_INFO["dnsrecon"]="pkg_manager|dnsrecon|DNS reconnaissance tool"
    TOOL_INSTALL_INFO["host"]="pkg_manager|bind-utils|DNS lookup utility"
    TOOL_INSTALL_INFO["dig"]="pkg_manager|bind-utils|DNS lookup tool"
    TOOL_INSTALL_INFO["nslookup"]="pkg_manager|bind-utils|DNS query tool"
    TOOL_INSTALL_INFO["whois"]="pkg_manager|whois|Domain registration information lookup"
    
    # 🌐 Web Application Security Testing (EXPANDED)
    TOOL_INSTALL_INFO["gobuster"]="pkg_manager|gobuster|Directory, file, and DNS enumeration"
    TOOL_INSTALL_INFO["ffuf"]="pkg_manager|ffuf|Fast web fuzzer with advanced filtering capabilities"
    TOOL_INSTALL_INFO["dirb"]="pkg_manager|dirb|Comprehensive web content scanner"
    TOOL_INSTALL_INFO["nikto"]="pkg_manager|nikto|Web server vulnerability scanner"
    TOOL_INSTALL_INFO["sqlmap"]="pkg_manager|sqlmap|Advanced automatic SQL injection testing"
    TOOL_INSTALL_INFO["wpscan"]="pkg_manager|wpscan|WordPress security scanner with vulnerability database"
    TOOL_INSTALL_INFO["burpsuite"]="manual_download|https://portswigger.net/burp/releases|Professional web security testing platform"
    TOOL_INSTALL_INFO["zaproxy"]="pkg_manager|zaproxy|OWASP ZAP web application security scanner"
    TOOL_INSTALL_INFO["arjun"]="pip_install|arjun|HTTP parameter discovery tool"
    TOOL_INSTALL_INFO["wafw00f"]="pkg_manager|wafw00f|Web application firewall fingerprinting"
    TOOL_INSTALL_INFO["feroxbuster"]="github_release|https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz|Fast content discovery tool"
    TOOL_INSTALL_INFO["dotdotpwn"]="github_manual|https://github.com/wireghoul/dotdotpwn|Directory traversal fuzzer"
    TOOL_INSTALL_INFO["xsser"]="pkg_manager|xsser|Cross-site scripting detection and exploitation"
    TOOL_INSTALL_INFO["wfuzz"]="pkg_manager|wfuzz|Web application fuzzer"
    TOOL_INSTALL_INFO["dirsearch"]="github_manual|https://github.com/maurosoria/dirsearch|Web path discovery tool"
    TOOL_INSTALL_INFO["katana"]="go_install|github.com/projectdiscovery/katana/cmd/katana|Web crawler"
    TOOL_INSTALL_INFO["dalfox"]="go_install|github.com/hahwul/dalfox/v2|XSS scanner and utility"
    TOOL_INSTALL_INFO["hakrawler"]="go_install|github.com/hakluke/hakrawler|Fast web endpoint discovery and crawling"
    TOOL_INSTALL_INFO["paramspider"]="github_manual|https://github.com/devanshbatham/ParamSpider|Mining parameters from web archives"
    TOOL_INSTALL_INFO["aquatone"]="github_release|https://github.com/michenriksen/aquatone/releases/latest/download/aquatone_linux_amd64_1.7.0.zip|Visual inspection of websites"
    TOOL_INSTALL_INFO["subjack"]="go_install|github.com/haccer/subjack|Subdomain takeover vulnerability checker"
    TOOL_INSTALL_INFO["waybackurls"]="go_install|github.com/tomnomnom/waybackurls|Extract URLs from Wayback Machine"
    TOOL_INSTALL_INFO["gau"]="go_install|github.com/lc/gau/v2/cmd/gau|Get All URLs"
    TOOL_INSTALL_INFO["meg"]="go_install|github.com/tomnomnom/meg|Fetch URLs without getting overwhelmed"
    TOOL_INSTALL_INFO["httprobe"]="go_install|github.com/tomnomnom/httprobe|Probe for working HTTP and HTTPS servers"
    TOOL_INSTALL_INFO["unfurl"]="go_install|github.com/tomnomnom/unfurl|Pull out bits of URLs"
    TOOL_INSTALL_INFO["anew"]="go_install|github.com/tomnomnom/anew|Append lines to files without duplicates"
    TOOL_INSTALL_INFO["qsreplace"]="go_install|github.com/tomnomnom/qsreplace|Query string replacement tool"
    TOOL_INSTALL_INFO["gospider"]="go_install|github.com/jaeles-project/gospider|Fast web spider"
    TOOL_INSTALL_INFO["gf"]="go_install|github.com/tomnomnom/gf|Wrapper around grep for specific patterns"
    TOOL_INSTALL_INFO["getjs"]="go_install|github.com/003random/getJS|Extract JavaScript files"
    TOOL_INSTALL_INFO["linkfinder"]="github_manual|https://github.com/GerbenJavado/LinkFinder|Discover endpoints in JavaScript files"
    TOOL_INSTALL_INFO["secretfinder"]="github_manual|https://github.com/m4ll0k/SecretFinder|Find secrets in JavaScript files"
    TOOL_INSTALL_INFO["jsscan"]="pip_install|jsscan|JavaScript static security analyzer"
    TOOL_INSTALL_INFO["subjs"]="go_install|github.com/lc/subjs|Fetch JavaScript files from subdomains"
    TOOL_INSTALL_INFO["urlprobe"]="go_install|github.com/1ndianl33t/urlprobe|Probe URLs for response codes"
    TOOL_INSTALL_INFO["corsy"]="github_manual|https://github.com/s0md3v/Corsy|CORS misconfiguration scanner"
    TOOL_INSTALL_INFO["xsstrike"]="github_manual|https://github.com/s0md3v/XSStrike|Advanced XSS detection suite"
    TOOL_INSTALL_INFO["commix"]="pkg_manager|commix|Command injection exploiter"
    TOOL_INSTALL_INFO["sqliv"]="github_manual|https://github.com/the-robot/sqliv|SQL injection vulnerability scanner"
    TOOL_INSTALL_INFO["nosqlmap"]="github_manual|https://github.com/codingo/NoSQLMap|NoSQL injection testing tool"
    TOOL_INSTALL_INFO["joomscan"]="pkg_manager|joomscan|Joomla vulnerability scanner"
    TOOL_INSTALL_INFO["droopescan"]="pip_install|droopescan|Drupal & SilverStripe scanner"
    TOOL_INSTALL_INFO["cmsmap"]="github_manual|https://github.com/Dionach/CMSmap|CMS security scanner"
    TOOL_INSTALL_INFO["whatweb"]="pkg_manager|whatweb|Web technology identifier"
    TOOL_INSTALL_INFO["webanalyze"]="go_install|github.com/rverton/webanalyze/cmd/webanalyze|Web technology analyzer"
    TOOL_INSTALL_INFO["wappalyzer"]="github_manual|https://github.com/AliasIO/wappalyzer|Technology profiler"
    TOOL_INSTALL_INFO["retire"]="npm_install|retire|JavaScript library scanner"
    TOOL_INSTALL_INFO["testssl"]="github_manual|https://github.com/drwetter/testssl.sh|SSL/TLS configuration checker"
    TOOL_INSTALL_INFO["sslyze"]="pip_install|sslyze|SSL configuration scanner"
    TOOL_INSTALL_INFO["sslscan"]="pkg_manager|sslscan|SSL cipher suite scanner"
    
    # 🔐 Authentication & Password Security (EXPANDED)
    TOOL_INSTALL_INFO["hydra"]="pkg_manager|hydra|Network login cracker supporting 50+ protocols"
    TOOL_INSTALL_INFO["john"]="pkg_manager|john|Advanced password hash cracking"
    TOOL_INSTALL_INFO["hashcat"]="pkg_manager|hashcat|World's fastest password recovery tool"
    TOOL_INSTALL_INFO["medusa"]="pkg_manager|medusa|Speedy, parallel, modular login brute-forcer"
    TOOL_INSTALL_INFO["patator"]="pkg_manager|patator|Multi-purpose brute-forcer"
    TOOL_INSTALL_INFO["crackmapexec"]="pip_install|crackmapexec|Swiss army knife for pentesting networks"
    TOOL_INSTALL_INFO["evil-winrm"]="pkg_manager|evil-winrm|Windows Remote Management shell"
    TOOL_INSTALL_INFO["hash-identifier"]="pkg_manager|hash-identifier|Hash type identifier"
    TOOL_INSTALL_INFO["ophcrack"]="pkg_manager|ophcrack|Windows password cracker"
    TOOL_INSTALL_INFO["hashid"]="pip_install|hashid|Hash identifier tool"
    TOOL_INSTALL_INFO["name-that-hash"]="pip_install|name-that-hash|Modern hash identification tool"
    TOOL_INSTALL_INFO["fcrackzip"]="pkg_manager|fcrackzip|ZIP password cracker"
    TOOL_INSTALL_INFO["pdfcrack"]="pkg_manager|pdfcrack|PDF password recovery tool"
    TOOL_INSTALL_INFO["rarcrack"]="pkg_manager|rarcrack|RAR/ZIP/7z password cracker"
    TOOL_INSTALL_INFO["bruteforce-luks"]="pkg_manager|bruteforce-luks|LUKS password cracker"
    TOOL_INSTALL_INFO["chntpw"]="pkg_manager|chntpw|NT password reset tool"
    TOOL_INSTALL_INFO["samdump2"]="pkg_manager|samdump2|SAM password hash dumper"
    TOOL_INSTALL_INFO["pwdump"]="github_manual|https://github.com/Neohapsis/creddump7|Windows password dump tool"
    TOOL_INSTALL_INFO["mimikatz"]="manual_download|https://github.com/gentilkiwi/mimikatz/releases|Windows credential extraction"
    TOOL_INSTALL_INFO["impacket"]="pip_install|impacket|Network protocol implementations"
    TOOL_INSTALL_INFO["bloodhound"]="github_release|https://github.com/BloodHoundAD/BloodHound/releases/latest|Active Directory attack path analysis"
    TOOL_INSTALL_INFO["kerbrute"]="go_install|github.com/ropnop/kerbrute|Kerberos bruteforce tool"
    TOOL_INSTALL_INFO["rubeus"]="manual_download|https://github.com/GhostPack/Rubeus/releases|Kerberos abuse toolkit"
    TOOL_INSTALL_INFO["powerview"]="github_manual|https://github.com/PowerShellMafia/PowerSploit|PowerShell AD enumeration"
    
    # 🔬 Binary Analysis & Reverse Engineering (EXPANDED)
    TOOL_INSTALL_INFO["gdb"]="pkg_manager|gdb|GNU Debugger with Python scripting"
    TOOL_INSTALL_INFO["radare2"]="pkg_manager|radare2|Advanced reverse engineering framework"
    TOOL_INSTALL_INFO["binwalk"]="pkg_manager|binwalk|Firmware analysis and extraction tool"
    TOOL_INSTALL_INFO["ropgadget"]="pip_install|ropgadget|ROP/JOP gadget finder"
    TOOL_INSTALL_INFO["checksec"]="pkg_manager|checksec|Binary security property checker"
    TOOL_INSTALL_INFO["strings"]="pkg_manager|binutils|Extract printable strings from binaries"
    TOOL_INSTALL_INFO["objdump"]="pkg_manager|binutils|Display object file information"
    TOOL_INSTALL_INFO["ghidra"]="manual_download|https://github.com/NationalSecurityAgency/ghidra/releases|NSA's software reverse engineering suite"
    TOOL_INSTALL_INFO["xxd"]="pkg_manager|xxd|Hex dump utility"
    TOOL_INSTALL_INFO["ida"]="manual_download|https://hex-rays.com/ida-free/|Interactive DisAssembler"
    TOOL_INSTALL_INFO["angr"]="pip_install|angr|Binary analysis platform"
    TOOL_INSTALL_INFO["pwntools"]="pip_install|pwntools|CTF framework and exploit development"
    TOOL_INSTALL_INFO["ropper"]="pip_install|ropper|ROP gadget finder"
    TOOL_INSTALL_INFO["one_gadget"]="gem_install|one_gadget|Magic gadget finder"
    TOOL_INSTALL_INFO["peda"]="github_manual|https://github.com/longld/peda|Python Exploit Development Assistance for GDB"
    TOOL_INSTALL_INFO["gef"]="github_manual|https://github.com/hugsy/gef|GDB Enhanced Features"
    TOOL_INSTALL_INFO["pwngdb"]="github_manual|https://github.com/scwuaptx/Pwngdb|GDB for pwn"
    TOOL_INSTALL_INFO["ltrace"]="pkg_manager|ltrace|Library call tracer"
    TOOL_INSTALL_INFO["strace"]="pkg_manager|strace|System call tracer"
    TOOL_INSTALL_INFO["valgrind"]="pkg_manager|valgrind|Memory error detector"
    TOOL_INSTALL_INFO["hexedit"]="pkg_manager|hexedit|Binary file editor"
    TOOL_INSTALL_INFO["bless"]="pkg_manager|bless|GUI hex editor"
    TOOL_INSTALL_INFO["upx"]="pkg_manager|upx-ucl|Ultimate packer for executables"
    TOOL_INSTALL_INFO["yara"]="pkg_manager|yara|Pattern matching engine"
    TOOL_INSTALL_INFO["pe-tree"]="pip_install|pe-tree|PE file analysis tool"
    TOOL_INSTALL_INFO["pestudio"]="manual_download|https://www.winitor.com/download|Windows PE analysis tool"
    TOOL_INSTALL_INFO["die"]="github_release|https://github.com/horsicq/Detect-It-Easy/releases|Detect It Easy file analyzer"
    TOOL_INSTALL_INFO["capa"]="pip_install|flare-capa|FLARE Capability Analysis"
    TOOL_INSTALL_INFO["floss"]="pip_install|flare-floss|FireEye Labs Obfuscated String Solver"
    
    # 🛡️ Exploitation & Post-Exploitation (NEW CATEGORY)
    TOOL_INSTALL_INFO["msfvenom"]="pkg_manager|metasploit-framework|Metasploit payload generator"
    TOOL_INSTALL_INFO["msfconsole"]="pkg_manager|metasploit-framework|Metasploit console"
    TOOL_INSTALL_INFO["searchsploit"]="pkg_manager|exploitdb|Exploit database search tool"
    TOOL_INSTALL_INFO["exploit-db"]="github_manual|https://github.com/offensive-security/exploitdb|Exploit database"
    TOOL_INSTALL_INFO["empire"]="github_manual|https://github.com/EmpireProject/Empire|PowerShell post-exploitation agent"
    TOOL_INSTALL_INFO["cobalt-strike"]="manual_download|https://www.cobaltstrike.com/|Commercial penetration testing software"
    TOOL_INSTALL_INFO["covenant"]="github_manual|https://github.com/cobbr/Covenant|.NET command and control framework"
    TOOL_INSTALL_INFO["sliver"]="github_release|https://github.com/BishopFox/sliver/releases|Command and control framework"
    TOOL_INSTALL_INFO["shellcode_launcher"]="github_manual|https://github.com/Arno0x/ShellcodeWrapper|Shellcode execution helper"
    TOOL_INSTALL_INFO["veil"]="github_manual|https://github.com/Veil-Framework/Veil|Metasploit payload evasion"
    TOOL_INSTALL_INFO["thefatrat"]="github_manual|https://github.com/screetsec/TheFatRat|Payload generator"
    TOOL_INSTALL_INFO["koadic"]="github_manual|https://github.com/zerosum0x0/koadic|JScript RAT"
    TOOL_INSTALL_INFO["pupy"]="github_manual|https://github.com/n1nj4sec/pupy|Cross-platform RAT"
    TOOL_INSTALL_INFO["beef"]="pkg_manager|beef-xss|Browser Exploitation Framework"
    
    # 🏆 Advanced CTF & Forensics Tools (EXPANDED)
    TOOL_INSTALL_INFO["volatility3"]="pip_install|volatility3|Advanced memory forensics framework"
    TOOL_INSTALL_INFO["volatility2"]="pip_install|volatility|Legacy memory forensics framework"
    TOOL_INSTALL_INFO["foremost"]="pkg_manager|foremost|File carving and data recovery"
    TOOL_INSTALL_INFO["steghide"]="pkg_manager|steghide|Steganography detection and extraction"
    TOOL_INSTALL_INFO["exiftool"]="pkg_manager|libimage-exiftool-perl|Metadata reader/writer for various file formats"
    TOOL_INSTALL_INFO["hashpump"]="github_manual|https://github.com/Phantomn/HashPump|Hash length extension attack tool"
    TOOL_INSTALL_INFO["sleuthkit"]="pkg_manager|sleuthkit|Collection of command-line digital forensics tools"
    TOOL_INSTALL_INFO["autopsy"]="manual_download|https://www.sleuthkit.org/autopsy/|Digital forensics platform"
    TOOL_INSTALL_INFO["bulk_extractor"]="pkg_manager|bulk-extractor|Digital forensics tool"
    TOOL_INSTALL_INFO["scalpel"]="pkg_manager|scalpel|Fast file carver"
    TOOL_INSTALL_INFO["photorec"]="pkg_manager|testdisk|Photo recovery software"
    TOOL_INSTALL_INFO["testdisk"]="pkg_manager|testdisk|Data recovery software"
    TOOL_INSTALL_INFO["recoverjpeg"]="pkg_manager|recoverjpeg|JPEG recovery tool"
    TOOL_INSTALL_INFO["safecopy"]="pkg_manager|safecopy|Data recovery tool"
    TOOL_INSTALL_INFO["ddrescue"]="pkg_manager|gddrescue|Data recovery tool"
    TOOL_INSTALL_INFO["extundelete"]="pkg_manager|extundelete|ext3/ext4 file recovery"
    TOOL_INSTALL_INFO["binutils"]="pkg_manager|binutils|Binary utilities collection"
    TOOL_INSTALL_INFO["file"]="pkg_manager|file|File type identification"
    TOOL_INSTALL_INFO["binutils"]="pkg_manager|binutils|Binary file analysis tools"
    TOOL_INSTALL_INFO["stegsolve"]="github_manual|https://github.com/zardus/ctf-tools|Steganography solver"
    TOOL_INSTALL_INFO["stegcracker"]="pip_install|stegcracker|Steganography brute-force tool"
   TOOL_INSTALL_INFO["zsteg"]="gem_install|zsteg|PNG/BMP steganography tool"
   TOOL_INSTALL_INFO["stegoVeritas"]="pip_install|stegoveritas|Steganography verification tool"
   TOOL_INSTALL_INFO["outguess"]="pkg_manager|outguess|Universal steganographic tool"
   TOOL_INSTALL_INFO["stegdetect"]="pkg_manager|stegdetect|Steganography detection tool"
   TOOL_INSTALL_INFO["jsteg"]="go_install|github.com/lukechampine/jsteg/cmd/jsteg|JPEG steganography"
   TOOL_INSTALL_INFO["lsb-toolkit"]="github_manual|https://github.com/luca-m/lsb-toolkit|LSB steganography toolkit"
   
   # ☁️ Cloud & Container Security (EXPANDED)
   TOOL_INSTALL_INFO["prowler"]="pip_install|prowler-cloud|AWS/Azure/GCP security assessment tool"
   TOOL_INSTALL_INFO["trivy"]="github_release|https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.50.1_Linux-64bit.tar.gz|Comprehensive vulnerability scanner for containers"
   TOOL_INSTALL_INFO["scout-suite"]="pip_install|scoutsuite|Multi-cloud security auditing tool"
   TOOL_INSTALL_INFO["kube-hunter"]="pip_install|kube-hunter|Kubernetes penetration testing tool"
   TOOL_INSTALL_INFO["kube-bench"]="github_release|https://github.com/aquasecurity/kube-bench/releases/latest/download/kube-bench_0.6.17_linux_amd64.tar.gz|CIS Kubernetes benchmark checker"
   TOOL_INSTALL_INFO["cloudsploit"]="github_manual|https://github.com/aquasecurity/cloudsploit|Cloud security scanning and monitoring"
   TOOL_INSTALL_INFO["pacu"]="github_manual|https://github.com/RhinoSecurityLabs/pacu|AWS exploitation framework"
   TOOL_INSTALL_INFO["cloudgoat"]="github_manual|https://github.com/RhinoSecurityLabs/cloudgoat|Vulnerable AWS environment"
   TOOL_INSTALL_INFO["grype"]="github_release|https://github.com/anchore/grype/releases/latest/download/grype_0.74.1_linux_amd64.tar.gz|Container vulnerability scanner"
   TOOL_INSTALL_INFO["syft"]="github_release|https://github.com/anchore/syft/releases/latest/download/syft_0.97.1_linux_amd64.tar.gz|Container SBOM generator"
   TOOL_INSTALL_INFO["docker-bench"]="github_manual|https://github.com/docker/docker-bench-security|Docker security benchmark"
   TOOL_INSTALL_INFO["clair"]="github_manual|https://github.com/quay/clair|Container vulnerability analysis"
   TOOL_INSTALL_INFO["anchore"]="pip_install|anchorecli|Container security analysis"
   TOOL_INSTALL_INFO["falco"]="github_manual|https://github.com/falcosecurity/falco|Container runtime security"
   TOOL_INSTALL_INFO["kubectl"]="manual_download|https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/|Kubernetes command-line tool"
   TOOL_INSTALL_INFO["helm"]="github_release|https://github.com/helm/helm/releases/latest|Kubernetes package manager"
   TOOL_INSTALL_INFO["istioctl"]="manual_download|https://istio.io/latest/docs/setup/getting-started/|Istio service mesh CLI"
   
   # 📱 Mobile Application Security (NEW CATEGORY)
   TOOL_INSTALL_INFO["apktool"]="manual_download|https://ibotpeaches.github.io/Apktool/|Android APK reverse engineering"
   TOOL_INSTALL_INFO["jadx"]="github_release|https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip|Android DEX decompiler"
   TOOL_INSTALL_INFO["dex2jar"]="manual_download|https://github.com/pxb1988/dex2jar/releases|DEX to JAR converter"
   TOOL_INSTALL_INFO["smali"]="manual_download|https://github.com/JesusFreke/smali/releases|Android bytecode assembler/disassembler"
   TOOL_INSTALL_INFO["baksmali"]="manual_download|https://github.com/JesusFreke/smali/releases|Android bytecode disassembler"
   TOOL_INSTALL_INFO["aapt"]="pkg_manager|aapt|Android Asset Packaging Tool"
   TOOL_INSTALL_INFO["adb"]="pkg_manager|android-tools-adb|Android Debug Bridge"
   TOOL_INSTALL_INFO["fastboot"]="pkg_manager|android-tools-fastboot|Android fastboot tool"
   TOOL_INSTALL_INFO["mobsf"]="github_manual|https://github.com/MobSF/Mobile-Security-Framework-MobSF|Mobile Security Framework"
   TOOL_INSTALL_INFO["qark"]="pip_install|qark|Quick Android Review Kit"
   TOOL_INSTALL_INFO["drozer"]="github_manual|https://github.com/WithSecureLabs/drozer|Android security testing framework"
   TOOL_INSTALL_INFO["frida"]="pip_install|frida-tools|Dynamic instrumentation toolkit"
   TOOL_INSTALL_INFO["objection"]="pip_install|objection|Runtime mobile exploration"
   TOOL_INSTALL_INFO["house"]="github_manual|https://github.com/nccgroup/house|Runtime mobile application analysis toolkit"
   TOOL_INSTALL_INFO["needle"]="github_manual|https://github.com/WithSecureLabs/needle|iOS security testing framework"
   TOOL_INSTALL_INFO["iproxy"]="pkg_manager|usbmuxd|iOS USB multiplexer daemon"
   TOOL_INSTALL_INFO["libimobiledevice"]="pkg_manager|libimobiledevice-utils|iOS device communication library"
   TOOL_INSTALL_INFO["ios-deploy"]="npm_install|ios-deploy|iOS app deployment tool"
   TOOL_INSTALL_INFO["class-dump"]="manual_download|http://stevenygard.com/projects/class-dump/|Objective-C class dumper"
   TOOL_INSTALL_INFO["otool"]="pkg_manager|cctools|Mach-O file analyzer"
   TOOL_INSTALL_INFO["hopper"]="manual_download|https://www.hopperapp.com/|Reverse engineering tool"
   
   # 🌐 Network & Wireless Security (NEW CATEGORY)
   TOOL_INSTALL_INFO["aircrack-ng"]="pkg_manager|aircrack-ng|WiFi security auditing tools suite"
   TOOL_INSTALL_INFO["reaver"]="pkg_manager|reaver|WPS brute force attack tool"
   TOOL_INSTALL_INFO["bully"]="pkg_manager|bully|WPS brute force tool"
   TOOL_INSTALL_INFO["wifite"]="pkg_manager|wifite|Automated wireless attack tool"
   TOOL_INSTALL_INFO["kismet"]="pkg_manager|kismet|Wireless network detector"
   TOOL_INSTALL_INFO["hostapd"]="pkg_manager|hostapd|IEEE 802.11 AP daemon"
   TOOL_INSTALL_INFO["dnsmasq"]="pkg_manager|dnsmasq|DNS/DHCP server"
   TOOL_INSTALL_INFO["ettercap"]="pkg_manager|ettercap|Network sniffer/interceptor"
   TOOL_INSTALL_INFO["wireshark"]="pkg_manager|wireshark|Network protocol analyzer"
   TOOL_INSTALL_INFO["tshark"]="pkg_manager|tshark|Network protocol analyzer CLI"
   TOOL_INSTALL_INFO["tcpdump"]="pkg_manager|tcpdump|Network packet analyzer"
   TOOL_INSTALL_INFO["ngrep"]="pkg_manager|ngrep|Network grep"
   TOOL_INSTALL_INFO["arp-scan"]="pkg_manager|arp-scan|ARP network scanner"
   TOOL_INSTALL_INFO["netdiscover"]="pkg_manager|netdiscover|Network address scanner"
   TOOL_INSTALL_INFO["fping"]="pkg_manager|fping|Fast ping scanner"
   TOOL_INSTALL_INFO["hping3"]="pkg_manager|hping3|Network packet crafting tool"
   TOOL_INSTALL_INFO["scapy"]="pip_install|scapy|Packet manipulation library"
   TOOL_INSTALL_INFO["yersinia"]="pkg_manager|yersinia|Layer 2 attack framework"
   TOOL_INSTALL_INFO["macchanger"]="pkg_manager|macchanger|MAC address changer"
   TOOL_INSTALL_INFO["proxychains"]="pkg_manager|proxychains|Proxy chains tool"
   TOOL_INSTALL_INFO["tor"]="pkg_manager|tor|The Onion Router"
   TOOL_INSTALL_INFO["openvpn"]="pkg_manager|openvpn|VPN client/server"
   TOOL_INSTALL_INFO["socat"]="pkg_manager|socat|Multipurpose relay tool"
   TOOL_INSTALL_INFO["netcat"]="pkg_manager|netcat|Network swiss army knife"
   TOOL_INSTALL_INFO["ncat"]="pkg_manager|nmap|Enhanced netcat"
   
   # 🔍 Information Gathering & OSINT (NEW CATEGORY)
   TOOL_INSTALL_INFO["maltego"]="manual_download|https://www.maltego.com/|Link analysis and data mining"
   TOOL_INSTALL_INFO["spiderfoot"]="github_manual|https://github.com/smicallef/spiderfoot|OSINT automation tool"
   TOOL_INSTALL_INFO["recon-ng"]="pkg_manager|recon-ng|Web reconnaissance framework"
   TOOL_INSTALL_INFO["osrframework"]="pip_install|osrframework|OSINT research framework"
   TOOL_INSTALL_INFO["sherlock"]="github_manual|https://github.com/sherlock-project/sherlock|Username investigation tool"
   TOOL_INSTALL_INFO["social-analyzer"]="github_manual|https://github.com/qeeqbox/social-analyzer|Social media analyzer"
   TOOL_INSTALL_INFO["photon"]="github_manual|https://github.com/s0md3v/Photon|Web crawler for OSINT"
   TOOL_INSTALL_INFO["metagoofil"]="github_manual|https://github.com/laramies/metagoofil|Metadata extraction tool"
   TOOL_INSTALL_INFO["foca"]="manual_download|https://github.com/ElevenPaths/FOCA|Fingerprinting Organizations with Collected Archives"
   TOOL_INSTALL_INFO["creepy"]="github_manual|https://github.com/ilektrojohn/creepy|Geolocation OSINT tool"
   TOOL_INSTALL_INFO["tinfoleak"]="github_manual|https://github.com/vaguileradiaz/tinfoleak|Twitter intelligence analysis"
   TOOL_INSTALL_INFO["twofi"]="github_manual|https://github.com/digininja/twofi|Twitter wordlist generator"
   TOOL_INSTALL_INFO["linkedin2username"]="github_manual|https://github.com/initstring/linkedin2username|LinkedIn username generator"
   TOOL_INSTALL_INFO["email2phonenumber"]="github_manual|https://github.com/martinvigo/email2phonenumber|Email to phone number"
   TOOL_INSTALL_INFO["gitrob"]="go_install|github.com/michenriksen/gitrob|GitHub sensitive data scanner"
   TOOL_INSTALL_INFO["truffleHog"]="go_install|github.com/trufflesecurity/trufflehog/v3/cmd/trufflehog|Git secrets scanner"
   TOOL_INSTALL_INFO["gitleaks"]="go_install|github.com/zricethezav/gitleaks/v8/cmd/gitleaks|Git secrets detection"
   TOOL_INSTALL_INFO["gitdumper"]="github_manual|https://github.com/internetwache/GitTools|Git repository dumper"
   TOOL_INSTALL_INFO["dvcs-ripper"]="github_manual|https://github.com/kost/dvcs-ripper|DVCS repository ripper"
   
   # 🧪 Vulnerability Scanners & Assessment (NEW CATEGORY)
   TOOL_INSTALL_INFO["openvas"]="pkg_manager|openvas|Comprehensive vulnerability scanner"
   TOOL_INSTALL_INFO["nessus"]="manual_download|https://www.tenable.com/downloads/nessus|Professional vulnerability scanner"
   TOOL_INSTALL_INFO["nexpose"]="manual_download|https://www.rapid7.com/products/nexpose/|Vulnerability management"
   TOOL_INSTALL_INFO["lynis"]="pkg_manager|lynis|Security auditing tool for Unix/Linux"
   TOOL_INSTALL_INFO["tiger"]="pkg_manager|tiger|Security auditing and intrusion detection"
   TOOL_INSTALL_INFO["rkhunter"]="pkg_manager|rkhunter|Rootkit hunter"
   TOOL_INSTALL_INFO["chkrootkit"]="pkg_manager|chkrootkit|Rootkit checker"
   TOOL_INSTALL_INFO["clamav"]="pkg_manager|clamav|Antivirus engine"
   TOOL_INSTALL_INFO["yersinia"]="pkg_manager|yersinia|Layer 2 vulnerability scanner"
   TOOL_INSTALL_INFO["sparta"]="github_manual|https://github.com/SECFORCE/sparta|Network penetration testing GUI"
   TOOL_INSTALL_INFO["legion"]="github_manual|https://github.com/carlospolop/legion|Network penetration testing tool"
   TOOL_INSTALL_INFO["faraday"]="pip_install|faradaysec|Collaborative penetration test IDE"
   TOOL_INSTALL_INFO["dradis"]="github_manual|https://github.com/dradis/dradis-ce|Collaboration and reporting platform"
   TOOL_INSTALL_INFO["magicTree"]="manual_download|https://www.gremwell.com/|Penetration testing productivity tool"
   
   # 🔐 Wireless & Radio Security (NEW CATEGORY)  
   TOOL_INSTALL_INFO["gqrx"]="pkg_manager|gqrx-sdr|Software defined radio receiver"
   TOOL_INSTALL_INFO["hackrf"]="pkg_manager|hackrf|HackRF software"
   TOOL_INSTALL_INFO["rtl-sdr"]="pkg_manager|rtl-sdr|RTL-SDR software"
   TOOL_INSTALL_INFO["gnuradio"]="pkg_manager|gnuradio|Software radio toolkit"
   TOOL_INSTALL_INFO["uhd"]="pkg_manager|uhd-host|USRP Hardware Driver"
   TOOL_INSTALL_INFO["chirp"]="pkg_manager|chirp|Radio programming tool"
   TOOL_INSTALL_INFO["multimon-ng"]="pkg_manager|multimon-ng|Digital transmission decoder"
   TOOL_INSTALL_INFO["dump1090"]="github_manual|https://github.com/antirez/dump1090|ADS-B decoder"
   TOOL_INSTALL_INFO["kalibrate-rtl"]="github_manual|https://github.com/steve-m/kalibrate-rtl|GSM frequency calibration"
   TOOL_INSTALL_INFO["gr-gsm"]="github_manual|https://github.com/ptrkrysik/gr-gsm|GSM analyzer for GNU Radio"
   TOOL_INSTALL_INFO["bladerf"]="pkg_manager|bladerf|BladeRF software"
   TOOL_INSTALL_INFO["limesdr"]="github_manual|https://github.com/myriadrf/LimeSuite|LimeSDR software suite"
   TOOL_INSTALL_INFO["rfcat"]="github_manual|https://github.com/atlas0fd00m/rfcat|RF analysis tool"
   TOOL_INSTALL_INFO["proxmark3"]="github_manual|https://github.com/RfidResearchGroup/proxmark3|RFID research tool"
   TOOL_INSTALL_INFO["flipper-zero"]="github_manual|https://github.com/flipperdevices/flipperzero-firmware|Multi-tool for pentesters"
   
   # 🌐 Advanced Web Security (NEW CATEGORY)
   TOOL_INSTALL_INFO["gospider"]="go_install|github.com/jaeles-project/gospider|Fast web spider"
   TOOL_INSTALL_INFO["gf"]="go_install|github.com/tomnomnom/gf|Wrapper around grep for specific patterns"
   TOOL_INSTALL_INFO["getjs"]="go_install|github.com/003random/getJS|Extract JavaScript files"
   TOOL_INSTALL_INFO["linkfinder"]="github_manual|https://github.com/GerbenJavado/LinkFinder|Discover endpoints in JavaScript files"
   TOOL_INSTALL_INFO["secretfinder"]="github_manual|https://github.com/m4ll0k/SecretFinder|Find secrets in JavaScript files"
   TOOL_INSTALL_INFO["jsscan"]="pip_install|jsscan|JavaScript static security analyzer"
   TOOL_INSTALL_INFO["subjs"]="go_install|github.com/lc/subjs|Fetch JavaScript files from subdomains"
   TOOL_INSTALL_INFO["urlprobe"]="go_install|github.com/1ndianl33t/urlprobe|Probe URLs for response codes"
   TOOL_INSTALL_INFO["corsy"]="github_manual|https://github.com/s0md3v/Corsy|CORS misconfiguration scanner"
   TOOL_INSTALL_INFO["xsstrike"]="github_manual|https://github.com/s0md3v/XSStrike|Advanced XSS detection suite"
   TOOL_INSTALL_INFO["commix"]="pkg_manager|commix|Command injection exploiter"
   TOOL_INSTALL_INFO["sqliv"]="github_manual|https://github.com/the-robot/sqliv|SQL injection vulnerability scanner"
   TOOL_INSTALL_INFO["nosqlmap"]="github_manual|https://github.com/codingo/NoSQLMap|NoSQL injection testing tool"
   TOOL_INSTALL_INFO["joomscan"]="pkg_manager|joomscan|Joomla vulnerability scanner"
   TOOL_INSTALL_INFO["droopescan"]="pip_install|droopescan|Drupal & SilverStripe scanner"
   TOOL_INSTALL_INFO["cmsmap"]="github_manual|https://github.com/Dionach/CMSmap|CMS security scanner"
   TOOL_INSTALL_INFO["whatweb"]="pkg_manager|whatweb|Web technology identifier"
   TOOL_INSTALL_INFO["webanalyze"]="go_install|github.com/rverton/webanalyze/cmd/webanalyze|Web technology analyzer"
   TOOL_INSTALL_INFO["wappalyzer"]="github_manual|https://github.com/AliasIO/wappalyzer|Technology profiler"
   TOOL_INSTALL_INFO["retire"]="npm_install|retire|JavaScript library scanner"
   TOOL_INSTALL_INFO["testssl"]="github_manual|https://github.com/drwetter/testssl.sh|SSL/TLS configuration checker"
   TOOL_INSTALL_INFO["sslyze"]="pip_install|sslyze|SSL configuration scanner"
   TOOL_INSTALL_INFO["sslscan"]="pkg_manager|sslscan|SSL cipher suite scanner"
   TOOL_INSTALL_INFO["ssldump"]="pkg_manager|ssldump|SSL/TLS network protocol analyzer"
   TOOL_INSTALL_INFO["sslstrip"]="pkg_manager|sslstrip|SSL stripping tool"
   TOOL_INSTALL_INFO["mitmproxy"]="pip_install|mitmproxy|Interactive TLS-capable intercepting proxy"
   TOOL_INSTALL_INFO["bettercap"]="github_release|https://github.com/bettercap/bettercap/releases/latest|Complete network reconnaissance and MITM framework"
   
   # 💀 Social Engineering & Phishing (NEW CATEGORY)
   TOOL_INSTALL_INFO["set"]="pkg_manager|set|Social Engineering Toolkit"
   TOOL_INSTALL_INFO["gophish"]="github_release|https://github.com/gophish/gophish/releases/latest|Open-source phishing toolkit"
   TOOL_INSTALL_INFO["king-phisher"]="github_manual|https://github.com/securestate/king-phisher|Phishing campaign toolkit"
   TOOL_INSTALL_INFO["evilginx2"]="github_manual|https://github.com/kgretzky/evilginx2|Advanced phishing framework"
   TOOL_INSTALL_INFO["modlishka"]="github_manual|https://github.com/drk1wi/Modlishka|Reverse proxy phishing tool"
   TOOL_INSTALL_INFO["blackeye"]="github_manual|https://github.com/An0nUD4Y/blackeye|Phishing page generator"
   TOOL_INSTALL_INFO["shellphish"]="github_manual|https://github.com/suljot/shellphish|Social engineering tool"
   TOOL_INSTALL_INFO["weeman"]="github_manual|https://github.com/evait-security/weeman|HTTP server for phishing"
   TOOL_INSTALL_INFO["fierce"]="pip_install|fierce|DNS reconnaissance tool"
   
   # 🔧 System & Privilege Escalation (NEW CATEGORY)
   TOOL_INSTALL_INFO["linpeas"]="github_manual|https://github.com/carlospolop/PEASS-ng|Linux privilege escalation checker"
   TOOL_INSTALL_INFO["winpeas"]="github_manual|https://github.com/carlospolop/PEASS-ng|Windows privilege escalation checker"
   TOOL_INSTALL_INFO["linenum"]="github_manual|https://github.com/rebootuser/LinEnum|Linux enumeration script"
   TOOL_INSTALL_INFO["unix-privesc-check"]="github_manual|https://github.com/pentestmonkey/unix-privesc-check|Unix privilege escalation checker"
   TOOL_INSTALL_INFO["linux-exploit-suggester"]="github_manual|https://github.com/mzet-/linux-exploit-suggester|Linux exploit suggester"
   TOOL_INSTALL_INFO["windows-exploit-suggester"]="github_manual|https://github.com/AonCyberLabs/Windows-Exploit-Suggester|Windows exploit suggester"
   TOOL_INSTALL_INFO["sherlock"]="github_manual|https://github.com/rasta-mouse/Sherlock|PowerShell script for privilege escalation"
   TOOL_INSTALL_INFO["powerup"]="github_manual|https://github.com/PowerShellMafia/PowerSploit|PowerShell privilege escalation"
   TOOL_INSTALL_INFO["pspy"]="github_release|https://github.com/DominicBreuker/pspy/releases/latest|Monitor Linux processes without root"
   TOOL_INSTALL_INFO["gtfobins"]="manual_reference|https://gtfobins.github.io/|Unix binaries privilege escalation reference"
   TOOL_INSTALL_INFO["lolbas"]="manual_reference|https://lolbas-project.github.io/|Living Off The Land Binaries and Scripts"
   
   # 🚗 Hardware & IoT Security (NEW CATEGORY)
   TOOL_INSTALL_INFO["firmadyne"]="github_manual|https://github.com/firmadyne/firmadyne|Firmware emulation and analysis"
   TOOL_INSTALL_INFO["firmware-mod-kit"]="github_manual|https://github.com/rampageX/firmware-mod-kit|Firmware modification toolkit"
   TOOL_INSTALL_INFO["binwalk"]="pkg_manager|binwalk|Firmware analysis and extraction tool"
   TOOL_INSTALL_INFO["sasquatch"]="github_manual|https://github.com/devttys0/sasquatch|SquashFS extraction tool"
   TOOL_INSTALL_INFO["jefferson"]="pip_install|jefferson|JFFS2 filesystem extraction"
   TOOL_INSTALL_INFO["ubi_reader"]="github_manual|https://github.com/jrspruitt/ubi_reader|UBI/UBIFS filesystem extraction"
   TOOL_INSTALL_INFO["cramfs-tools"]="pkg_manager|cramfsprogs|CramFS filesystem tools"
   TOOL_INSTALL_INFO["yaffs2utils"]="github_manual|https://github.com/bradfordboyle/yaffs2utils|YAFFS2 filesystem utilities"
   TOOL_INSTALL_INFO["openocd"]="pkg_manager|openocd|On-chip debugger"
   TOOL_INSTALL_INFO["avrdude"]="pkg_manager|avrdude|AVR microcontroller programmer"
   TOOL_INSTALL_INFO["esptool"]="pip_install|esptool|ESP32/ESP8266 flashing tool"
   TOOL_INSTALL_INFO["picotool"]="github_manual|https://github.com/raspberrypi/picotool|Raspberry Pi Pico tool"
   TOOL_INSTALL_INFO["bus-pirate"]="manual_download|http://dangerousprototypes.com/docs/Bus_Pirate|Universal bus interface"
   TOOL_INSTALL_INFO["arduino"]="pkg_manager|arduino|Arduino IDE"
   TOOL_INSTALL_INFO["minicom"]="pkg_manager|minicom|Serial communication program"
   TOOL_INSTALL_INFO["screen"]="pkg_manager|screen|Terminal multiplexer"
   TOOL_INSTALL_INFO["picocom"]="pkg_manager|picocom|Minimal serial communication program"
   
   # 🎯 Specialized Security Tools (NEW CATEGORY)
   TOOL_INSTALL_INFO["smbmap"]="pip_install|smbmap|SMB share enumeration tool"
   TOOL_INSTALL_INFO["smbclient"]="pkg_manager|smbclient|SMB client"
   TOOL_INSTALL_INFO["rpcclient"]="pkg_manager|samba-common-bin|RPC client for SMB"
   TOOL_INSTALL_INFO["enum4linux"]="pkg_manager|enum4linux|SMB enumeration tool"
   TOOL_INSTALL_INFO["ldapsearch"]="pkg_manager|ldap-utils|LDAP search tool"
   TOOL_INSTALL_INFO["ldapenum"]="github_manual|https://github.com/CroweCybersecurity/ad-ldap-enum|LDAP enumeration tool"
   TOOL_INSTALL_INFO["snmpwalk"]="pkg_manager|snmp|SNMP network scanner"
   TOOL_INSTALL_INFO["snmpcheck"]="github_manual|https://github.com/dheiland-r7/snmpcheck|SNMP enumeration tool"
   TOOL_INSTALL_INFO["onesixtyone"]="pkg_manager|onesixtyone|SNMP scanner"
   TOOL_INSTALL_INFO["snmpenum"]="github_manual|https://github.com/SECFORCE/SNMPBrute|SNMP enumeration script"
   TOOL_INSTALL_INFO["nbtscan"]="pkg_manager|nbtscan|NetBIOS name scanner"
   TOOL_INSTALL_INFO["rpcinfo"]="pkg_manager|rpcbind|RPC service information"
   TOOL_INSTALL_INFO["showmount"]="pkg_manager|nfs-common|NFS mount information"
   TOOL_INSTALL_INFO["rpcbind"]="pkg_manager|rpcbind|RPC port mapper"
   TOOL_INSTALL_INFO["smtp-user-enum"]="pkg_manager|smtp-user-enum|SMTP user enumeration"
   TOOL_INSTALL_INFO["ike-scan"]="pkg_manager|ike-scan|IPsec VPN scanner"
   TOOL_INSTALL_INFO["vpnc"]="pkg_manager|vpnc|Cisco VPN client"
   TOOL_INSTALL_INFO["openconnect"]="pkg_manager|openconnect|Multi-protocol VPN client"
   
   # 🎪 CTF & Competition Tools (NEW CATEGORY)
   TOOL_INSTALL_INFO["pwntools"]="pip_install|pwntools|CTF framework and exploit development"
   TOOL_INSTALL_INFO["z3"]="pip_install|z3-solver|Theorem prover for CTF"
   TOOL_INSTALL_INFO["sage"]="pip_install|sage|Mathematical software for cryptography"
   TOOL_INSTALL_INFO["gmpy2"]="pip_install|gmpy2|Multiple precision arithmetic"
   TOOL_INSTALL_INFO["sympy"]="pip_install|sympy|Symbolic mathematics"
   TOOL_INSTALL_INFO["pycrypto"]="pip_install|pycryptodome|Cryptographic library"
   TOOL_INSTALL_INFO["requests"]="pip_install|requests|HTTP library"
   TOOL_INSTALL_INFO["beautifulsoup4"]="pip_install|beautifulsoup4|Web scraping library"
   TOOL_INSTALL_INFO["selenium"]="pip_install|selenium|Web browser automation"
   TOOL_INSTALL_INFO["pillow"]="pip_install|pillow|Image processing library"
   TOOL_INSTALL_INFO["opencv-python"]="pip_install|opencv-python|Computer vision library"
   TOOL_INSTALL_INFO["numpy"]="pip_install|numpy|Numerical computing library"
   TOOL_INSTALL_INFO["matplotlib"]="pip_install|matplotlib|Plotting library"
   TOOL_INSTALL_INFO["pwn"]="pip_install|pwntools|Binary exploitation framework"
   TOOL_INSTALL_INFO["roputils"]="pip_install|roputils|ROP exploitation utilities"
   TOOL_INSTALL_INFO["capstone"]="pip_install|capstone|Disassembly framework"
   TOOL_INSTALL_INFO["keystone"]="pip_install|keystone-engine|Assembly framework"
   TOOL_INSTALL_INFO["unicorn"]="pip_install|unicorn|CPU emulator framework"
   
   # 🔍 Forensics & Analysis (EXPANDED)
   TOOL_INSTALL_INFO["autopsy"]="manual_download|https://www.sleuthkit.org/autopsy/|Digital forensics platform"
   TOOL_INSTALL_INFO["bulk_extractor"]="pkg_manager|bulk-extractor|Digital forensics tool"
   TOOL_INSTALL_INFO["scalpel"]="pkg_manager|scalpel|Fast file carver"
   TOOL_INSTALL_INFO["photorec"]="pkg_manager|testdisk|Photo recovery software"
   TOOL_INSTALL_INFO["testdisk"]="pkg_manager|testdisk|Data recovery software"
   TOOL_INSTALL_INFO["recoverjpeg"]="pkg_manager|recoverjpeg|JPEG recovery tool"
   TOOL_INSTALL_INFO["safecopy"]="pkg_manager|safecopy|Data recovery tool"
   TOOL_INSTALL_INFO["ddrescue"]="pkg_manager|gddrescue|Data recovery tool"
   TOOL_INSTALL_INFO["extundelete"]="pkg_manager|extundelete|ext3/ext4 file recovery"
   TOOL_INSTALL_INFO["dc3dd"]="pkg_manager|dc3dd|Enhanced dd for forensics"
   TOOL_INSTALL_INFO["dcfldd"]="pkg_manager|dcfldd|Enhanced dd with hashing"
   TOOL_INSTALL_INFO["ewf-tools"]="pkg_manager|ewf-tools|Expert Witness Format tools"
   TOOL_INSTALL_INFO["afflib-tools"]="pkg_manager|afflib-tools|Advanced Forensics Format tools"
   TOOL_INSTALL_INFO["libewf"]="pkg_manager|libewf-tools|Expert Witness Format library"
   TOOL_INSTALL_INFO["plaso"]="pip_install|plaso|Super timeline all the things"
   TOOL_INSTALL_INFO["log2timeline"]="pip_install|plaso|Timeline creation tool"
   TOOL_INSTALL_INFO["mactime"]="pkg_manager|sleuthkit|Timeline analysis tool"
   TOOL_INSTALL_INFO["fls"]="pkg_manager|sleuthkit|File system analysis tool"
   TOOL_INSTALL_INFO["icat"]="pkg_manager|sleuthkit|File content extraction"
   TOOL_INSTALL_INFO["mmls"]="pkg_manager|sleuthkit|Media management tool"
   TOOL_INSTALL_INFO["fsstat"]="pkg_manager|sleuthkit|File system statistics"
   TOOL_INSTALL_INFO["regripper"]="github_manual|https://github.com/keydet89/RegRipper3.0|Windows registry analysis"
   TOOL_INSTALL_INFO["hivex"]="pkg_manager|libhivex-bin|Windows registry hive extraction"
   TOOL_INSTALL_INFO["chntpw"]="pkg_manager|chntpw|Windows password recovery"
   TOOL_INSTALL_INFO["rifiuti2"]="github_manual|https://github.com/abelcheung/rifiuti2|Windows recycle bin analysis"
   TOOL_INSTALL_INFO["tsk_recover"]="pkg_manager|sleuthkit|File recovery tool"
   TOOL_INSTALL_INFO["disktype"]="pkg_manager|disktype|Disk format detection"
   TOOL_INSTALL_INFO["pcapfix"]="pkg_manager|pcapfix|PCAP file repair tool"
   TOOL_INSTALL_INFO["tcpflow"]="pkg_manager|tcpflow|TCP connection reconstruction"
   TOOL_INSTALL_INFO["tcpick"]="pkg_manager|tcpick|TCP stream sniffer"
   TOOL_INSTALL_INFO["driftnet"]="pkg_manager|driftnet|Image extraction from network traffic"
   TOOL_INSTALL_INFO["tcpxtract"]="pkg_manager|tcpxtract|Extract files from network traffic"
   TOOL_INSTALL_INFO["xplico"]="pkg_manager|xplico|Network forensic analysis tool"
   
   # 🏢 Enterprise Security & Active Directory (NEW CATEGORY)
   TOOL_INSTALL_INFO["bloodhound"]="github_release|https://github.com/BloodHoundAD/BloodHound/releases/latest|Active Directory attack path analysis"
   TOOL_INSTALL_INFO["sharphound"]="github_manual|https://github.com/BloodHoundAD/SharpHound|BloodHound ingestor"
   TOOL_INSTALL_INFO["azurehound"]="github_manual|https://github.com/BloodHoundAD/AzureHound|Azure enumeration for BloodHound"
   TOOL_INSTALL_INFO["powerview"]="github_manual|https://github.com/PowerShellMafia/PowerSploit|PowerShell AD enumeration"
   TOOL_INSTALL_INFO["adrecon"]="github_manual|https://github.com/adrecon/ADRecon|Active Directory reconnaissance"
   TOOL_INSTALL_INFO["ldapdomaindump"]="pip_install|ldapdomaindump|LDAP domain information dumper"
   TOOL_INSTALL_INFO["windapsearch"]="github_manual|https://github.com/ropnop/windapsearch|LDAP enumeration tool"
   TOOL_INSTALL_INFO["kerbrute"]="go_install|github.com/ropnop/kerbrute|Kerberos bruteforce tool"
   TOOL_INSTALL_INFO["rubeus"]="manual_download|https://github.com/GhostPack/Rubeus/releases|Kerberos abuse toolkit"
   TOOL_INSTALL_INFO["mimikatz"]="manual_download|https://github.com/gentilkiwi/mimikatz/releases|Windows credential extraction"
   TOOL_INSTALL_INFO["pypykatz"]="pip_install|pypykatz|Python implementation of mimikatz"
   TOOL_INSTALL_INFO["lsassy"]="pip_install|lsassy|Remote LSASS dumping and parsing"
   TOOL_INSTALL_INFO["sprayhound"]="github_manual|https://github.com/Hackndo/sprayhound|Password spraying tool"
   TOOL_INSTALL_INFO["dcsync"]="manual_reference|https://attack.mitre.org/techniques/T1003/006/|DCSync attack reference"
   TOOL_INSTALL_INFO["golden-ticket"]="manual_reference|https://attack.mitre.org/techniques/T1558/001/|Golden ticket attack reference"
   TOOL_INSTALL_INFO["silver-ticket"]="manual_reference|https://attack.mitre.org/techniques/T1558/002/|Silver ticket attack reference"
   TOOL_INSTALL_INFO["kerberoast"]="github_manual|https://github.com/GhostPack/Rubeus|Kerberoasting attack tool"
   TOOL_INSTALL_INFO["asreproast"]="github_manual|https://github.com/GhostPack/Rubeus|AS-REP roasting attack tool"
   TOOL_INSTALL_INFO["ntlmrelayx"]="pip_install|impacket|NTLM relay attack tool"
   TOOL_INSTALL_INFO["responder"]="pkg_manager|responder|LLMNR/NBT-NS/MDNS poisoner"
   
   # 🚀 Automation & Orchestration (NEW CATEGORY)
   TOOL_INSTALL_INFO["ansible"]="pip_install|ansible|IT automation platform"
   TOOL_INSTALL_INFO["terraform"]="manual_download|https://www.terraform.io/downloads|Infrastructure as code"
   TOOL_INSTALL_INFO["docker"]="pkg_manager|docker.io|Containerization platform"
   TOOL_INSTALL_INFO["kubernetes"]="manual_download|https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/|Container orchestration"
   TOOL_INSTALL_INFO["vagrant"]="manual_download|https://www.vagrantup.com/downloads|Development environment manager"
   TOOL_INSTALL_INFO["packer"]="manual_download|https://www.packer.io/downloads|Image builder"
   TOOL_INSTALL_INFO["consul"]="manual_download|https://www.consul.io/downloads|Service discovery"
   TOOL_INSTALL_INFO["vault"]="manual_download|https://www.vaultproject.io/downloads|Secrets management"
   TOOL_INSTALL_INFO["nomad"]="manual_download|https://www.nomadproject.io/downloads|Workload orchestrator"
   
   # 🎲 Miscellaneous Security Tools (NEW CATEGORY)
   TOOL_INSTALL_INFO["curl"]="pkg_manager|curl|Command line HTTP client"
   TOOL_INSTALL_INFO["wget"]="pkg_manager|wget|Web content retriever"
   TOOL_INSTALL_INFO["jq"]="pkg_manager|jq|JSON processor"
   TOOL_INSTALL_INFO["xmllint"]="pkg_manager|libxml2-utils|XML processor"
   TOOL_INSTALL_INFO["base64"]="pkg_manager|coreutils|Base64 encoder/decoder"
   TOOL_INSTALL_INFO["openssl"]="pkg_manager|openssl|Cryptographic toolkit"
   TOOL_INSTALL_INFO["gpg"]="pkg_manager|gnupg|GNU Privacy Guard"
   TOOL_INSTALL_INFO["ssh"]="pkg_manager|openssh-client|SSH client"
   TOOL_INSTALL_INFO["scp"]="pkg_manager|openssh-client|Secure copy"
   TOOL_INSTALL_INFO["rsync"]="pkg_manager|rsync|File synchronization"
   TOOL_INSTALL_INFO["git"]="pkg_manager|git|Version control system"
   TOOL_INSTALL_INFO["vim"]="pkg_manager|vim|Text editor"
   TOOL_INSTALL_INFO["nano"]="pkg_manager|nano|Text editor"
   TOOL_INSTALL_INFO["tmux"]="pkg_manager|tmux|Terminal multiplexer"
   TOOL_INSTALL_INFO["screen"]="pkg_manager|screen|Terminal multiplexer"
   TOOL_INSTALL_INFO["htop"]="pkg_manager|htop|Process viewer"
   TOOL_INSTALL_INFO["iftop"]="pkg_manager|iftop|Network bandwidth monitor"
   TOOL_INSTALL_INFO["iotop"]="pkg_manager|iotop|I/O monitor"
   TOOL_INSTALL_INFO["nethogs"]="pkg_manager|nethogs|Network traffic monitor per process"
   TOOL_INSTALL_INFO["lsof"]="pkg_manager|lsof|List open files"
   TOOL_INSTALL_INFO["netstat"]="pkg_manager|net-tools|Network connections"
   TOOL_INSTALL_INFO["ss"]="pkg_manager|iproute2|Socket statistics"
   TOOL_INSTALL_INFO["ps"]="pkg_manager|procps|Process status"
   TOOL_INSTALL_INFO["top"]="pkg_manager|procps|Process viewer"
   TOOL_INSTALL_INFO["grep"]="pkg_manager|grep|Text search tool"
   TOOL_INSTALL_INFO["sed"]="pkg_manager|sed|Stream editor"
   TOOL_INSTALL_INFO["awk"]="pkg_manager|gawk|Text processing"
   TOOL_INSTALL_INFO["find"]="pkg_manager|findutils|File search"
   TOOL_INSTALL_INFO["locate"]="pkg_manager|mlocate|File location database"
   TOOL_INSTALL_INFO["which"]="pkg_manager|which|Command location finder"
   TOOL_INSTALL_INFO["whereis"]="pkg_manager|util-linux|Binary location finder"
   TOOL_INSTALL_INFO["man"]="pkg_manager|man-db|Manual pages"
   TOOL_INSTALL_INFO["info"]="pkg_manager|info|Info documents"
   TOOL_INSTALL_INFO["help"]="built_in|help|Built-in help system"
}

# Function to get package name based on distribution
get_package_name() {
   local tool=$1
   
   case $DISTRO in
       "ubuntu"|"debian"|"kali"|"parrot"|"mint")
           case $tool in
               "theharvester") echo "theharvester" ;;
               "evil-winrm") echo "evil-winrm" ;;
               "hash-identifier") echo "hash-identifier" ;;
               "enum4linux-ng") echo "enum4linux-ng" ;;
               "httpx") echo "httpx-toolkit" ;;
               "volatility3") echo "volatility3" ;;
               "netexec") echo "netexec" ;;
               "exiftool") echo "libimage-exiftool-perl" ;;
               "zaproxy") echo "zaproxy" ;;
               "sleuthkit") echo "sleuthkit" ;;
               "metasploit-framework") echo "metasploit-framework" ;;
               "xxd") echo "xxd" ;;
               "bind-utils") echo "dnsutils" ;;
               "android-tools-adb") echo "adb" ;;
               "android-tools-fastboot") echo "fastboot" ;;
               "libimage-exiftool-perl") echo "libimage-exiftool-perl" ;;
               "libxml2-utils") echo "libxml2-utils" ;;
               "net-tools") echo "net-tools" ;;
               "iproute2") echo "iproute2" ;;
               *) echo "$tool" ;;
           esac
           ;;
       "fedora"|"rhel"|"centos")
           case $tool in
               "theharvester") echo "theHarvester" ;;
               "evil-winrm") echo "rubygem-evil-winrm" ;;
               "enum4linux-ng") echo "enum4linux-ng" ;;
               "httpx") echo "httpx" ;;
               "volatility3") echo "python3-volatility3" ;;
               "exiftool") echo "perl-Image-ExifTool" ;;
               "zaproxy") echo "zaproxy" ;;
               "sleuthkit") echo "sleuthkit" ;;
               "metasploit-framework") echo "metasploit" ;;
               "xxd") echo "vim-common" ;;
               "bind-utils") echo "bind-utils" ;;
               "libxml2-utils") echo "libxml2" ;;
               "net-tools") echo "net-tools" ;;
               "iproute2") echo "iproute" ;;
               *) echo "$tool" ;;
           esac
           ;;
       "arch"|"manjaro"|"endeavouros")
           case $tool in
               "theharvester") echo "theharvester" ;;
               "evil-winrm") echo "evil-winrm" ;;
               "hash-identifier") echo "hash-identifier" ;;
               "enum4linux-ng") echo "enum4linux-ng" ;;
               "httpx") echo "httpx" ;;
               "volatility3") echo "volatility3" ;;
               "exiftool") echo "perl-image-exiftool" ;;
               "zaproxy") echo "zaproxy" ;;
               "sleuthkit") echo "sleuthkit" ;;
               "metasploit-framework") echo "metasploit" ;;
               "xxd") echo "xxd" ;;
               "bind-utils") echo "bind-tools" ;;
               "libxml2-utils") echo "libxml2" ;;
               "net-tools") echo "net-tools" ;;
               "iproute2") echo "iproute2" ;;
               *) echo "$tool" ;;
           esac
           ;;
       *)
           echo "$tool"
           ;;
   esac
}

# Function to check if a command exists (ENHANCED)
check_tool() {
   local tool=$1
   local alt_check=$2
   local category=${3:-"General"}
   
   TOTAL_COUNT=$((TOTAL_COUNT + 1))
   
   # Check primary command
   if command -v "$tool" > /dev/null 2>&1; then
       echo -e "✅ ${GREEN}$tool${NC} - ${GREEN}INSTALLED${NC} ${BLUE}($category)${NC}"
       INSTALLED_TOOLS+=("$tool")
       INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
       return 0
   fi
   
   # Check alternative command if provided
   if [ -n "$alt_check" ] && command -v "$alt_check" > /dev/null 2>&1; then
       echo -e "✅ ${GREEN}$tool${NC} (as $alt_check) - ${GREEN}INSTALLED${NC} ${BLUE}($category)${NC}"
       INSTALLED_TOOLS+=("$tool")
       INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
       return 0
   fi
   
   # Check if it's a Python package that might be installed
   if python3 -c "import $tool" > /dev/null 2>&1; then
       echo -e "✅ ${GREEN}$tool${NC} (Python package) - ${GREEN}INSTALLED${NC} ${BLUE}($category)${NC}"
       INSTALLED_TOOLS+=("$tool")
       INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
       return 0
   fi
   
   # Check common installation locations (EXPANDED)
   local locations=(
       "/usr/bin/$tool"
       "/usr/local/bin/$tool"
       "/opt/$tool"
       "/home/$USER/tools/$tool"
       "/home/$USER/Desktop/$tool"
       "/usr/share/$tool"
       "/snap/bin/$tool"
       "/usr/local/share/$tool"
       "/var/lib/gems/*/bin/$tool"
       "/usr/local/go/bin/$tool"
       "$HOME/go/bin/$tool"
       "$HOME/.cargo/bin/$tool"
       "$HOME/.local/bin/$tool"
       "/usr/games/$tool"
       "/usr/sbin/$tool"
       "/sbin/$tool"
   )
   
   for location in "${locations[@]}"; do
       if [ -f "$location" ] || [ -d "$location" ]; then
           echo -e "✅ ${GREEN}$tool${NC} - ${GREEN}INSTALLED${NC} (found at $location) ${BLUE}($category)${NC}"
           INSTALLED_TOOLS+=("$tool")
           INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
           return 0
       fi
   done
   
   # Tool not found
   local package_name=$(get_package_name "$tool")
   echo -e "❌ ${RED}$tool${NC} - ${RED}NOT INSTALLED${NC} ${YELLOW}($PKG_MANAGER install $package_name)${NC} ${BLUE}($category)${NC}"
   MISSING_TOOLS+=("$tool:$package_name:$category")
   MISSING_COUNT=$((MISSING_COUNT + 1))
   return 1
}

# Enhanced installation commands generator
generate_verified_install_commands() {
   if [ $MISSING_COUNT -eq 0 ]; then
       return
   fi
   
   echo -e "${YELLOW}${BOLD}📦 HEXSTRIKE AI OFFICIAL INSTALLATION COMMANDS (v4.0):${NC}"
   echo "=================================================================="
   
   local PKG_MANAGER_TOOLS=""
   local GO_TOOLS=""
   local PIP_TOOLS=""
   local NPM_TOOLS=""
   local GEM_TOOLS=""
   local GITHUB_RELEASES=""
   local MANUAL_INSTALLS=""
   local FAILED_VERIFICATIONS=""
   
   # Categorize missing tools
   declare -A CATEGORY_COUNTS
   for missing in "${MISSING_TOOLS[@]}"; do
       local tool=$(echo "$missing" | cut -d':' -f1)
       local package=$(echo "$missing" | cut -d':' -f2)
       local category=$(echo "$missing" | cut -d':' -f3)
       
       CATEGORY_COUNTS["$category"]=$((${CATEGORY_COUNTS["$category"]} + 1))
       
       if [ -n "${TOOL_INSTALL_INFO[$tool]}" ]; then
           IFS='|' read -r install_type install_info description <<< "${TOOL_INSTALL_INFO[$tool]}"
           
           case $install_type in
               "pkg_manager")
                   PKG_MANAGER_TOOLS+=" $package"
                   ;;
               
               "go_install")
                   echo -e "${BLUE}🔍 Verifying Go package: $install_info${NC}"
                   if check_url "https://$install_info"; then
                       GO_TOOLS+="\\n  go install -v $install_info@latest  # $tool - $description"
                       echo -e "  ✅ ${GREEN}Verified${NC}"
                   else
                       GO_TOOLS+="\\n  go install -v $install_info@latest  # $tool - $description (⚠️ Could not verify)"
                       echo -e "  ⚠️  ${YELLOW}Could not verify URL${NC}"
                   fi
                   ;;
               
               "pip_install")
                   PIP_TOOLS+="\\n  pip3 install $install_info  # $tool - $description"
                   ;;
               
               "npm_install")
                   NPM_TOOLS+="\\n  npm install -g $install_info  # $tool - $description"
                   ;;
               
               "gem_install")
                   GEM_TOOLS+="\\n  gem install $install_info  # $tool - $description"
                   ;;
               
               "github_release")
                   echo -e "${BLUE}🔍 Verifying GitHub release: $install_info${NC}"
                   if check_url "$install_info"; then
                       GITHUB_RELEASES+="\\n# $tool - $description\\nwget $install_info\\n"
                       echo -e "  ✅ ${GREEN}Download link verified${NC}"
                   else
                       local base_url=$(echo "$install_info" | sed 's|/releases/latest/download/.*|/releases|')
                       GITHUB_RELEASES+="\\n# $tool - $description\\n# ⚠️  Direct link failed, visit: $base_url\\n"
                       FAILED_VERIFICATIONS+="\\n❌ $tool: $install_info"
                       echo -e "  ❌ ${RED}Download link failed - check manually${NC}"
                   fi
                   ;;
               
               "github_manual"|"manual_download")
                   echo -e "${BLUE}🔍 Verifying manual install: $install_info${NC}"
                   if check_url "$install_info"; then
                       if [[ "$install_type" == "github_manual" ]]; then
                           MANUAL_INSTALLS+="\\n# $tool - $description\\ngit clone $install_info\\ncd $(basename $install_info)\\n# Follow installation instructions in README\\n"
                       else
                           MANUAL_INSTALLS+="\\n# $tool - $description\\n# Download from: $install_info\\n# Extract and follow installation instructions\\n"
                       fi
                       echo -e "  ✅ ${GREEN}URL verified${NC}"
                   else
                       MANUAL_INSTALLS+="\\n# $tool - $description\\n# ⚠️  URL failed: $install_info\\n"
                       FAILED_VERIFICATIONS+="\\n❌ $tool: $install_info"
                       echo -e "  ❌ ${RED}URL not accessible${NC}"
                   fi
                   ;;
               
               "manual_reference")
                   MANUAL_INSTALLS+="\\n# $tool - $description\\n# Reference: $install_info\\n"
                   ;;
               
               "built_in")
                   # Skip built-in tools
                   ;;
           esac
       else
           PKG_MANAGER_TOOLS+=" $package"
       fi
   done
   
   echo ""
   echo -e "${PURPLE}📊 Missing Tools by Category:${NC}"
   for category in "${!CATEGORY_COUNTS[@]}"; do
       echo -e "  ${CYAN}$category${NC}: ${CATEGORY_COUNTS[$category]} tools"
   done
   echo ""
   
   # Display installation commands
   if [ -n "$PKG_MANAGER_TOOLS" ]; then
       echo -e "${CYAN}📦 Package Manager Installation ($PKG_MANAGER):${NC}"
       echo "$INSTALL_CMD$PKG_MANAGER_TOOLS"
       echo ""
   fi
   
   if [ -n "$PIP_TOOLS" ]; then
       echo -e "${CYAN}🐍 Python Package Installation:${NC}"
       echo -e "$PIP_TOOLS"
       echo ""
   fi
   
   if [ -n "$GO_TOOLS" ]; then
       echo -e "${CYAN}🐹 Go Package Installation (requires Go):${NC}"
       echo "# First install Go if not present:"
       case $DISTRO in
           "ubuntu"|"debian"|"kali"|"parrot"|"mint")
               echo "sudo apt install golang-go"
               ;;
           "fedora"|"rhel"|"centos")
               echo "sudo $PKG_MANAGER install go"
               ;;
           "arch"|"manjaro"|"endeavouros")
               echo "sudo pacman -S go"
               ;;
       esac
       echo -e "$GO_TOOLS"
       echo ""
   fi
   
   if [ -n "$NPM_TOOLS" ]; then
       echo -e "${CYAN}📦 NPM Package Installation (requires Node.js):${NC}"
       echo "# First install Node.js and npm if not present"
       echo -e "$NPM_TOOLS"
       echo ""
   fi
   
   if [ -n "$GEM_TOOLS" ]; then
       echo -e "${CYAN}💎 Ruby Gem Installation (requires Ruby):${NC}"
       echo "# First install Ruby and gem if not present"
       echo -e "$GEM_TOOLS"
       echo ""
   fi
   
   if [ -n "$GITHUB_RELEASES" ]; then
       echo -e "${CYAN}📁 GitHub Releases (Verified Links):${NC}"
       echo -e "$GITHUB_RELEASES"
       echo ""
   fi
   
   if [ -n "$MANUAL_INSTALLS" ]; then
       echo -e "${CYAN}🔧 Manual Installations:${NC}"
       echo -e "$MANUAL_INSTALLS"
       echo ""
   fi
   
   if [ -n "$FAILED_VERIFICATIONS" ]; then
       echo -e "${RED}⚠️  Failed Link Verifications:${NC}"
       echo -e "$FAILED_VERIFICATIONS"
       echo -e "\\n${YELLOW}💡 For failed links, please check the official project repositories manually.${NC}"
       echo ""
   fi
   
   # MEGA INSTALLATION COMMANDS (ENHANCED)
   echo -e "${GREEN}🚀 HEXSTRIKE AI MEGA INSTALLATION COMMAND (150+ TOOLS):${NC}"
   echo "=================================================================="
   case $DISTRO in
       "ubuntu"|"debian"|"kali"|"parrot"|"mint")
           echo "# Core System & Network tools"
           echo "sudo apt update && sudo apt install -y curl wget git vim nano tmux screen htop iftop iotop nethogs lsof net-tools iproute2 dnsutils whois"
           echo ""
           echo "# Network & Reconnaissance tools"
           echo "sudo apt install -y nmap masscan amass fierce dnsenum theharvester responder netexec enum4linux-ng rustscan arp-scan netdiscover fping hping3 yersinia macchanger proxychains tor openvpn socat netcat"
           echo ""
           echo "# Web Application Security tools"
           echo "sudo apt install -y gobuster ffuf dirb nikto sqlmap wpscan wafw00f zaproxy xsser wfuzz commix whatweb sslscan testssl.sh retire.js"
           echo ""
           echo "# Password & Authentication tools"
           echo "sudo apt install -y hydra john hashcat medusa patator evil-winrm hash-identifier ophcrack fcrackzip pdfcrack rarcrack bruteforce-luks chntpw samdump2"
           echo ""
           echo "# Binary Analysis & Reverse Engineering tools"
           echo "sudo apt install -y gdb radare2 binwalk checksec binutils foremost steghide libimage-exiftool-perl sleuthkit xxd metasploit-framework ltrace strace valgrind hexedit bless upx-ucl yara"
           echo ""
           echo "# Forensics & Analysis tools"
           echo "sudo apt install -y autopsy bulk-extractor scalpel testdisk recoverjpeg safecopy gddrescue extundelete dc3dd dcfldd ewf-tools afflib-tools libewf-tools libhivex-bin pcapfix tcpflow tcpick driftnet tcpxtract"
           echo ""
           echo "# Wireless & Network Security tools"
           echo "sudo apt install -y aircrack-ng reaver bully wifite kismet hostapd dnsmasq ettercap wireshark tshark tcpdump ngrep"
           echo ""
           echo "# Mobile & Hardware Security tools"
           echo "sudo apt install -y aapt adb fastboot usbmuxd libimobiledevice-utils android-tools-adb android-tools-fastboot"
           echo ""
           echo "# Vulnerability Scanners & Assessment tools"
           echo "sudo apt install -y openvas lynis tiger rkhunter chkrootkit clamav set"
           echo ""
           echo "# Specialized Security tools"
           echo "sudo apt install -y smbclient samba-common-bin ldap-utils snmp onesixtyone nbtscan rpcbind nfs-common smtp-user-enum ike-scan vpnc openconnect"
           echo ""
           echo "# Radio & SDR tools"
           echo "sudo apt install -y gqrx-sdr hackrf rtl-sdr gnuradio uhd-host chirp multimon-ng bladerf"
           echo ""
           echo "# Development & Build tools"
           echo "sudo apt install -y build-essential python3-pip python3-dev golang-go nodejs npm ruby ruby-dev libxml2-utils jq openssl gnupg openssh-client rsync"
           echo ""
           echo "# Python packages (MASSIVE LIST)"
           echo "pip3 install autorecon ropgadget arjun crackmapexec netexec volatility3 prowler-cloud scoutsuite kube-hunter smbmap shodan censys fierce impacket pypykatz lsassy ldapdomaindump sprayhound hashid name-that-hash pwntools z3-solver sympy pycryptodome requests beautifulsoup4 selenium pillow opencv-python numpy matplotlib capstone-engine keystone-engine unicorn ropper droopescan sslyze mitmproxy plaso scapy angr frida-tools objection qark osrframework jefferson esptool jsscan stegcracker stegoveritas faradaysec"
           echo ""
           echo "# Go packages (COMPREHENSIVE LIST)"
           echo "go install github.com/owasp-amass/amass/v4/cmd/amass@latest"
           echo "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
           echo "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
           echo "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
           echo "go install github.com/projectdiscovery/katana/cmd/katana@latest"
           echo "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
           echo "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
           echo "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
           echo "go install github.com/projectdiscovery/uncover/cmd/uncover@latest"
           echo "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
           echo "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
           echo "go install github.com/hahwul/dalfox/v2@latest"
           echo "go install github.com/hakluke/hakrawler@latest"
           echo "go install github.com/haccer/subjack@latest"
           echo "go install github.com/tomnomnom/assetfinder@latest"
           echo "go install github.com/tomnomnom/waybackurls@latest"
           echo "go install github.com/lc/gau/v2/cmd/gau@latest"
           echo "go install github.com/tomnomnom/meg@latest"
           echo "go install github.com/tomnomnom/httprobe@latest"
           echo "go install github.com/tomnomnom/unfurl@latest"
           echo "go install github.com/tomnomnom/anew@latest"
           echo "go install github.com/tomnomnom/qsreplace@latest"
           echo "go install github.com/tomnomnom/gf@latest"
           echo "go install github.com/003random/getJS@latest"
           echo "go install github.com/lc/subjs@latest"
           echo "go install github.com/1ndianl33t/urlprobe@latest"
           echo "go install github.com/jaeles-project/gospider@latest"
           echo "go install github.com/rverton/webanalyze/cmd/webanalyze@latest"
           echo "go install github.com/michenriksen/gitrob@latest"
           echo "go install github.com/trufflesecurity/trufflehog/v3/cmd/trufflehog@latest"
           echo "go install github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest"
           echo "go install github.com/ropnop/kerbrute@latest"
           echo "go install github.com/lukechampine/jsteg/cmd/jsteg@latest"
           echo ""
           echo "# Ruby gems"
           echo "gem install one_gadget zsteg"
           echo ""
           echo "# Node.js packages"
           echo "npm install -g retire @angular/cli ios-deploy"
           ;;
       "fedora"|"rhel"|"centos")
           echo "# Similar structure for Red Hat based systems..."
           echo "# Core System & Network tools"
           echo "sudo $PKG_MANAGER install -y curl wget git vim nano tmux screen htop iftop iotop nethogs lsof net-tools iproute bind-utils whois"
           echo ""
           echo "# Network & Reconnaissance tools"
           echo "sudo $PKG_MANAGER install -y nmap masscan dnsenum theHarvester arp-scan netdiscover fping hping3 macchanger proxychains-ng tor openvpn socat nc"
           echo ""
           echo "# Web Application Security tools"
           echo "sudo $PKG_MANAGER install -y gobuster ffuf dirb nikto sqlmap zaproxy wfuzz whatweb sslscan"
           echo ""
           echo "# Password & Authentication tools"
           echo "sudo $PKG_MANAGER install -y hydra john hashcat medusa patator rubygem-evil-winrm fcrackzip"
           echo ""
           echo "# Binary Analysis & Reverse Engineering tools"
           echo "sudo $PKG_MANAGER install -y gdb radare2 binwalk binutils foremost steghide perl-Image-ExifTool sleuthkit vim-common ltrace strace valgrind hexedit upx yara"
           echo ""
           echo "# Python packages (same as Ubuntu)"
           echo "pip3 install autorecon ropgadget arjun crackmapexec netexec volatility3 prowler-cloud scoutsuite kube-hunter smbmap shodan censys fierce impacket pypykatz lsassy ldapdomaindump hashid name-that-hash pwntools z3-solver sympy pycryptodome requests beautifulsoup4 selenium pillow opencv-python numpy matplotlib capstone-engine keystone-engine unicorn ropper droopescan sslyze mitmproxy plaso scapy angr frida-tools objection qark osrframework jefferson esptool jsscan stegcracker stegoveritas faradaysec"
           ;;
       "arch"|"manjaro"|"endeavouros")
           echo "# Arch Linux installation commands..."
           echo "# Core System & Network tools"
           echo "sudo pacman -S curl wget git vim nano tmux screen htop iftop iotop nethogs lsof net-tools iproute2 bind-tools whois"
           echo ""
           echo "# Network & Reconnaissance tools" 
           echo "sudo pacman -S nmap masscan dnsenum theharvester arp-scan netdiscover fping hping macchanger proxychains-ng tor openvpn socat gnu-netcat"
           echo ""
           echo "# Web Application Security tools"
           echo "sudo pacman -S gobuster ffuf dirb nikto sqlmap zaproxy wfuzz sslscan"
           echo ""
           echo "# Password & Authentication tools"
           echo "sudo pacman -S hydra john hashcat medusa patator evil-winrm hash-identifier ophcrack fcrackzip"
           echo ""
           echo "# Binary Analysis & Reverse Engineering tools"
           echo "sudo pacman -S gdb radare2 binwalk binutils foremost steghide perl-image-exiftool sleuthkit xxd ltrace strace valgrind bless upx yara"
           echo ""
           echo "# Python packages (same as Ubuntu)"
           echo "pip3 install autorecon ropgadget arjun crackmapexec netexec volatility3 prowler-cloud scoutsuite kube-hunter smbmap shodan censys fierce impacket pypykatz lsassy ldapdomaindump hashid name-that-hash pwntools z3-solver sympy pycryptodome requests beautifulsoup4 selenium pillow opencv-python numpy matplotlib capstone-engine keystone-engine unicorn ropper droopescan sslyze mitmproxy plaso scapy angr frida-tools objection qark osrframework jefferson esptool jsscan stegcracker stegoveritas faradaysec"
           ;;
   esac
   echo ""
   echo -e "${GREEN}🌟 HEXSTRIKE AI POST-INSTALLATION SETUP:${NC}"
   echo "# Create tools directory structure"
   echo "mkdir -p ~/tools/{wordlists,scripts,exploits,payloads}"
   echo ""
   echo "# Download essential wordlists"
   echo "cd ~/tools/wordlists"
   echo "wget https://github.com/danielmiessler/SecLists/archive/master.zip -O seclists.zip"
   echo "unzip seclists.zip && rm seclists.zip"
   echo "git clone https://github.com/berzerk0/Probable-Wordlists.git"
   echo "wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
   echo ""
   echo "# Download essential exploit databases"
   echo "cd ~/tools/exploits"
   echo "git clone https://github.com/offensive-security/exploitdb.git"
   echo "git clone https://github.com/nomi-sec/PoC-in-GitHub.git"
   echo ""
   echo "# Set up Nuclei templates"
   echo "nuclei -update-templates"
   echo ""
   echo "# Update all package managers"
   echo "sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian"
   echo "pip3 install --upgrade pip"
   echo "go install -a std"
   echo "gem update --system"
   echo "npm update -g"
   echo ""
}

# Main execution
echo -e "${ORANGE}🔍 Initializing complete HexStrike AI tool database (150+ tools)...${NC}"
init_complete_tool_database

detect_distro
get_package_manager

if [ "$CURL_AVAILABLE" = false ]; then
   echo -e "${YELLOW}⚠️  curl not found. Link verification disabled. Install curl for full functionality.${NC}"
   echo ""
fi

# Enhanced tool checking with categories
echo -e "${MAGENTA}${BOLD}🔍 Network Reconnaissance & Scanning Tools${NC}"
echo "================================================"
check_tool "nmap" "" "Network Scanning"
check_tool "amass" "" "Subdomain Enumeration"
check_tool "subfinder" "" "Subdomain Discovery"
check_tool "nuclei" "" "Vulnerability Scanning"
check_tool "autorecon" "" "Automated Reconnaissance"
check_tool "fierce" "" "DNS Reconnaissance"
check_tool "masscan" "" "Port Scanning"
check_tool "theharvester" "" "OSINT"
check_tool "responder" "" "Network Poisoning"
check_tool "netexec" "nxc" "Network Exploitation"
check_tool "enum4linux-ng" "" "SMB Enumeration"
check_tool "dnsenum" "" "DNS Enumeration"
check_tool "dnsrecon" "" "DNS Reconnaissance"
check_tool "rustscan" "" "Fast Port Scanning"
check_tool "shodan" "" "Internet Scanning"
check_tool "censys" "" "Internet Scanning"
check_tool "naabu" "" "Port Discovery"
check_tool "httpx" "" "HTTP Toolkit"
check_tool "uncover" "" "Search Engine Discovery"
check_tool "mapcidr" "" "CIDR Manipulation"
check_tool "chaos" "" "Passive DNS"
check_tool "dnsx" "" "DNS Toolkit"
check_tool "shuffledns" "" "DNS Resolution"
check_tool "assetfinder" "" "Asset Discovery"
check_tool "findomain" "" "Subdomain Discovery"
check_tool "host" "" "DNS Lookup"
check_tool "dig" "" "DNS Lookup"
check_tool "nslookup" "" "DNS Query"
check_tool "whois" "" "Domain Information"
echo ""

echo -e "${MAGENTA}${BOLD}🌐 Web Application Security Testing Tools${NC}"
echo "================================================"
check_tool "gobuster" "" "Directory Enumeration"
check_tool "ffuf" "" "Web Fuzzing"
check_tool "dirb" "" "Web Content Scanning"
check_tool "nikto" "" "Web Vulnerability Scanning"
check_tool "sqlmap" "" "SQL Injection Testing"
check_tool "wpscan" "" "WordPress Security"
check_tool "burpsuite" "" "Web Security Testing"
check_tool "zaproxy" "zap" "Web Application Scanner"
check_tool "arjun" "" "Parameter Discovery"
check_tool "wafw00f" "" "WAF Detection"
check_tool "feroxbuster" "" "Content Discovery"
check_tool "dotdotpwn" "" "Directory Traversal"
check_tool "xsser" "" "XSS Detection"
check_tool "wfuzz" "" "Web Fuzzing"
check_tool "dirsearch" "" "Web Path Discovery"
check_tool "katana" "" "Web Crawling"
check_tool "dalfox" "" "XSS Scanner"
check_tool "hakrawler" "" "Web Endpoint Discovery"
check_tool "paramspider" "" "Parameter Mining"
check_tool "aquatone" "" "Website Inspection"
check_tool "subjack" "" "Subdomain Takeover"
check_tool "waybackurls" "" "URL Discovery"
check_tool "gau" "" "URL Collection"
check_tool "meg" "" "URL Fetching"
check_tool "httprobe" "" "HTTP/HTTPS Probing"
check_tool "unfurl" "" "URL Analysis"
check_tool "anew" "" "Unique Line Addition"
check_tool "qsreplace" "" "Query String Replacement"
check_tool "gospider" "" "Web Spider"
check_tool "gf" "" "Pattern Matching"
check_tool "getjs" "" "JavaScript Extraction"
check_tool "linkfinder" "" "Endpoint Discovery"
check_tool "secretfinder" "" "Secret Discovery"
check_tool "jsscan" "" "JavaScript Security"
check_tool "subjs" "" "JavaScript Enumeration"
check_tool "urlprobe" "" "URL Probing"
check_tool "corsy" "" "CORS Testing"
check_tool "xsstrike" "" "XSS Detection"
check_tool "commix" "" "Command Injection"
check_tool "sqliv" "" "SQL Injection Scanner"
check_tool "nosqlmap" "" "NoSQL Injection"
check_tool "joomscan" "" "Joomla Security"
check_tool "droopescan" "" "CMS Security"
check_tool "cmsmap" "" "CMS Security"
check_tool "whatweb" "" "Web Technology"
check_tool "webanalyze" "" "Technology Analysis"
check_tool "retire" "" "JavaScript Library Scanner"
check_tool "testssl" "" "SSL/TLS Testing"
check_tool "sslyze" "" "SSL Scanner"
check_tool "sslscan" "" "SSL Cipher Scanner"
check_tool "ssldump" "" "SSL Analysis"
check_tool "sslstrip" "" "SSL Stripping"
check_tool "mitmproxy" "" "Proxy Interception"
check_tool "bettercap" "" "Network Reconnaissance"
echo ""

echo -e "${MAGENTA}${BOLD}🔐 Authentication & Password Security Tools${NC}"
echo "================================================"
check_tool "hydra" "" "Network Login Cracking"
check_tool "john" "" "Password Hash Cracking"
check_tool "hashcat" "" "Password Recovery"
check_tool "medusa" "" "Login Brute-forcer"
check_tool "patator" "" "Multi-purpose Brute-forcer"
check_tool "crackmapexec" "cme" "Network Pentesting"
check_tool "evil-winrm" "" "WinRM Shell"
check_tool "hash-identifier" "" "Hash Identification"
check_tool "ophcrack" "" "Windows Password Cracking"
check_tool "hashid" "" "Hash Identifier"
check_tool "name-that-hash" "" "Modern Hash ID"
check_tool "fcrackzip" "" "ZIP Password Cracking"
check_tool "pdfcrack" "" "PDF Password Recovery"
check_tool "rarcrack" "" "Archive Password Cracking"
check_tool "bruteforce-luks" "" "LUKS Password Cracking"
check_tool "chntpw" "" "NT Password Reset"
check_tool "samdump2" "" "SAM Hash Dumper"
check_tool "mimikatz" "" "Windows Credential Extraction"
check_tool "impacket" "" "Network Protocol Implementations"
check_tool "bloodhound" "" "AD Attack Paths"
check_tool "kerbrute" "" "Kerberos Bruteforce"
check_tool "pypykatz" "" "Python Mimikatz"
check_tool "lsassy" "" "Remote LSASS Dumping"
echo ""

echo -e "${MAGENTA}${BOLD}🔬 Binary Analysis & Reverse Engineering Tools${NC}"
echo "================================================"
check_tool "gdb" "" "Debugging"
check_tool "radare2" "r2" "Reverse Engineering"
check_tool "binwalk" "" "Firmware Analysis"
check_tool "ropgadget" "" "ROP Gadget Finding"
check_tool "checksec" "" "Binary Security"
check_tool "strings" "" "String Extraction"
check_tool "objdump" "" "Object Analysis"
check_tool "ghidra" "" "Software Reverse Engineering"
check_tool "xxd" "" "Hex Dump"
check_tool "angr" "" "Binary Analysis"
check_tool "pwntools" "" "Exploit Development"
check_tool "ropper" "" "ROP Gadget Finder"
check_tool "one_gadget" "" "Magic Gadget Finder"
check_tool "peda" "" "GDB Enhancement"
check_tool "gef" "" "GDB Enhanced Features"
check_tool "pwngdb" "" "GDB for PWN"
check_tool "ltrace" "" "Library Call Tracer"
check_tool "strace" "" "System Call Tracer"
check_tool "valgrind" "" "Memory Error Detector"
check_tool "hexedit" "" "Binary Editor"
check_tool "bless" "" "GUI Hex Editor"
check_tool "upx" "" "Executable Packer"
check_tool "yara" "" "Pattern Matching"
check_tool "pe-tree" "" "PE Analysis"
check_tool "capa" "" "Capability Analysis"
check_tool "floss" "" "Obfuscated String Solver"
echo ""

echo -e "${MAGENTA}${BOLD}🛡️ Exploitation & Post-Exploitation Tools${NC}"
echo "================================================"
check_tool "msfvenom" "" "Payload Generation"
check_tool "msfconsole" "" "Metasploit Console"
check_tool "searchsploit" "" "Exploit Database Search"
check_tool "empire" "" "PowerShell Post-exploitation"
check_tool "sliver" "" "Command & Control"
check_tool "beef" "" "Browser Exploitation"
check_tool "veil" "" "Payload Evasion"
check_tool "koadic" "" "JScript RAT"
check_tool "pupy" "" "Cross-platform RAT"
echo ""

echo -e "${MAGENTA}${BOLD}🏆 Advanced CTF & Forensics Tools${NC}"
echo "================================================"
check_tool "volatility3" "vol3" "Memory Forensics"
check_tool "volatility2" "vol" "Legacy Memory Forensics"
check_tool "foremost" "" "File Carving"
check_tool "steghide" "" "Steganography"
check_tool "exiftool" "" "Metadata Analysis"
check_tool "hashpump" "" "Hash Length Extension"
check_tool "sleuthkit" "" "Digital Forensics"
check_tool "autopsy" "" "Forensics Platform"
check_tool "bulk_extractor" "" "Digital Forensics"
check_tool "scalpel" "" "File Carver"
check_tool "photorec" "" "Photo Recovery"
check_tool "testdisk" "" "Data Recovery"
check_tool "recoverjpeg" "" "JPEG Recovery"
check_tool "safecopy" "" "Data Recovery"
check_tool "ddrescue" "" "Data Recovery"
check_tool "extundelete" "" "File Recovery"
check_tool "stegcracker" "" "Steganography Brute-force"
check_tool "zsteg" "" "PNG/BMP Steganography"
check_tool "stegoveritas" "" "Steganography Verification"
check_tool "outguess" "" "Universal Steganography"
check_tool "stegdetect" "" "Steganography Detection"
check_tool "jsteg" "" "JPEG Steganography"
check_tool "dc3dd" "" "Forensic Imaging"
check_tool "dcfldd" "" "Enhanced DD"
check_tool "ewf-tools" "" "Expert Witness Format"
check_tool "afflib-tools" "" "Advanced Forensics Format"
check_tool "plaso" "" "Timeline Analysis"
check_tool "regripper" "" "Windows Registry Analysis"
check_tool "hivex" "" "Registry Extraction"
check_tool "rifiuti2" "" "Recycle Bin Analysis"
check_tool "pcapfix" "" "PCAP Repair"
check_tool "tcpflow" "" "TCP Reconstruction"
check_tool "tcpick" "" "TCP Stream Sniffer"
check_tool "driftnet" "" "Image Extraction"
check_tool "tcpxtract" "" "File Extraction"
echo ""

echo -e "${MAGENTA}${BOLD}☁️ Cloud & Container Security Tools${NC}"
echo "================================================"
check_tool "prowler" "" "Cloud Security Assessment"
check_tool "trivy" "" "Container Vulnerability Scanner"
check_tool "scout-suite" "" "Multi-cloud Auditing"
check_tool "kube-hunter" "" "Kubernetes Penetration Testing"
check_tool "kube-bench" "" "Kubernetes Benchmark"
check_tool "cloudsploit" "" "Cloud Security Scanning"
check_tool "pacu" "" "AWS Exploitation"
check_tool "cloudgoat" "" "Vulnerable AWS Environment"
check_tool "grype" "" "Container Vulnerability Scanner"
check_tool "syft" "" "Container SBOM Generator"
check_tool "docker-bench" "" "Docker Security Benchmark"
check_tool "clair" "" "Container Vulnerability Analysis"
check_tool "anchore" "" "Container Security"
check_tool "falco" "" "Container Runtime Security"
check_tool "kubectl" "" "Kubernetes CLI"
check_tool "helm" "" "Kubernetes Package Manager"
echo ""

echo -e "${MAGENTA}${BOLD}📱 Mobile Application Security Tools${NC}"
echo "================================================"
check_tool "apktool" "" "Android APK Reverse Engineering"
check_tool "jadx" "" "Android DEX Decompiler"
check_tool "dex2jar" "" "DEX to JAR Converter"
check_tool "aapt" "" "Android Asset Packaging"
check_tool "adb" "" "Android Debug Bridge"
check_tool "fastboot" "" "Android Fastboot"
check_tool "mobsf" "" "Mobile Security Framework"
check_tool "qark" "" "Quick Android Review Kit"
check_tool "drozer" "" "Android Security Testing"
check_tool "frida" "" "Dynamic Instrumentation"
check_tool "objection" "" "Runtime Mobile Exploration"
check_tool "needle" "" "iOS Security Testing"
check_tool "libimobiledevice" "" "iOS Communication Library"
echo ""

echo -e "${MAGENTA}${BOLD}🌐 Network & Wireless Security Tools${NC}"
echo "================================================"
check_tool "aircrack-ng" "" "WiFi Security Auditing"
check_tool "reaver" "" "WPS Brute Force"
check_tool "bully" "" "WPS Brute Force"
check_tool "wifite" "" "Automated Wireless Attack"
check_tool "kismet" "" "Wireless Network Detector"
check_tool "hostapd" "" "IEEE 802.11 AP"
check_tool "dnsmasq" "" "DNS/DHCP Server"
check_tool "ettercap" "" "Network Interceptor"
check_tool "wireshark" "" "Network Protocol Analyzer"
check_tool "tshark" "" "Network Protocol CLI"
check_tool "tcpdump" "" "Network Packet Analyzer"
check_tool "ngrep" "" "Network Grep"
check_tool "arp-scan" "" "ARP Network Scanner"
check_tool "netdiscover" "" "Network Address Scanner"
check_tool "fping" "" "Fast Ping Scanner"
check_tool "hping3" "" "Packet Crafting"
check_tool "scapy" "" "Packet Manipulation"
check_tool "yersinia" "" "Layer 2 Attacks"
check_tool "macchanger" "" "MAC Address Changer"
check_tool "proxychains" "" "Proxy Chains"
check_tool "tor" "" "The Onion Router"
check_tool "openvpn" "" "VPN Client/Server"
check_tool "socat" "" "Multipurpose Relay"
check_tool "netcat" "nc" "Network Swiss Army Knife"
echo ""

echo -e "${MAGENTA}${BOLD}🔍 Information Gathering & OSINT Tools${NC}"
echo "================================================"
check_tool "maltego" "" "Link Analysis"
check_tool "spiderfoot" "" "OSINT Automation"
check_tool "recon-ng" "" "Web Reconnaissance Framework"
check_tool "osrframework" "" "OSINT Research Framework"
check_tool "sherlock" "" "Username Investigation"
check_tool "social-analyzer" "" "Social Media Analyzer"
check_tool "photon" "" "Web Crawler for OSINT"
check_tool "metagoofil" "" "Metadata Extraction"
check_tool "creepy" "" "Geolocation OSINT"
check_tool "tinfoleak" "" "Twitter Intelligence"
check_tool "twofi" "" "Twitter Wordlist Generator"
check_tool "gitrob" "" "GitHub Sensitive Data Scanner"
check_tool "trufflehog" "" "Git Secrets Scanner"
check_tool "gitleaks" "" "Git Secrets Detection"
echo ""

echo -e "${MAGENTA}${BOLD}🧪 Vulnerability Scanners & Assessment Tools${NC}"
echo "================================================"
check_tool "openvas" "" "Vulnerability Scanner"
check_tool "nessus" "" "Professional Vulnerability Scanner"
check_tool "lynis" "" "Security Auditing"
check_tool "tiger" "" "Security Auditing"
check_tool "rkhunter" "" "Rootkit Hunter"
check_tool "chkrootkit" "" "Rootkit Checker"
check_tool "clamav" "" "Antivirus Engine"
check_tool "sparta" "" "Network Penetration Testing GUI"
check_tool "legion" "" "Network Penetration Testing"
check_tool "faraday" "" "Collaborative Pentest IDE"
echo ""

echo -e "${MAGENTA}${BOLD}🔐 Wireless & Radio Security Tools${NC}"
echo "================================================"
check_tool "gqrx" "" "Software Defined Radio"
check_tool "hackrf" "" "HackRF Software"
check_tool "rtl-sdr" "" "RTL-SDR Software"
check_tool "gnuradio" "" "Software Radio Toolkit"
check_tool "uhd" "" "USRP Hardware Driver"
check_tool "chirp" "" "Radio Programming"
check_tool "multimon-ng" "" "Digital Transmission Decoder"
check_tool "dump1090" "" "ADS-B Decoder"
check_tool "kalibrate-rtl" "" "GSM Frequency Calibration"
check_tool "gr-gsm" "" "GSM Analyzer"
check_tool "bladerf" "" "BladeRF Software"
check_tool "rfcat" "" "RF Analysis"
check_tool "proxmark3" "" "RFID Research"
echo ""

echo -e "${MAGENTA}${BOLD}💀 Social Engineering & Phishing Tools${NC}"
echo "================================================"
check_tool "set" "" "Social Engineering Toolkit"
check_tool "gophish" "" "Phishing Toolkit"
check_tool "king-phisher" "" "Phishing Campaign Toolkit"
check_tool "evilginx2" "" "Advanced Phishing Framework"
check_tool "modlishka" "" "Reverse Proxy Phishing"
check_tool "blackeye" "" "Phishing Page Generator"
check_tool "shellphish" "" "Social Engineering Tool"
check_tool "weeman" "" "HTTP Server for Phishing"
echo ""

echo -e "${MAGENTA}${BOLD}🔧 System & Privilege Escalation Tools${NC}"
echo "================================================"
check_tool "linpeas" "" "Linux Privilege Escalation"
check_tool "winpeas" "" "Windows Privilege Escalation"
check_tool "linenum" "" "Linux Enumeration"
check_tool "unix-privesc-check" "" "Unix Privilege Escalation Checker"
check_tool "linux-exploit-suggester" "" "Linux Exploit Suggester"
check_tool "windows-exploit-suggester" "" "Windows Exploit Suggester"
check_tool "powerup" "" "PowerShell Privilege Escalation"
check_tool "pspy" "" "Process Monitor"
echo ""

echo -e "${MAGENTA}${BOLD}🚗 Hardware & IoT Security Tools${NC}"
echo "================================================"
check_tool "firmadyne" "" "Firmware Emulation"
check_tool "firmware-mod-kit" "" "Firmware Modification"
check_tool "sasquatch" "" "SquashFS Extraction"
check_tool "jefferson" "" "JFFS2 Extraction"
check_tool "ubi_reader" "" "UBI/UBIFS Extraction"
check_tool "cramfs-tools" "" "CramFS Tools"
check_tool "openocd" "" "On-chip Debugger"
check_tool "avrdude" "" "AVR Programmer"
check_tool "esptool" "" "ESP32/ESP8266 Flashing"
check_tool "arduino" "" "Arduino IDE"
check_tool "minicom" "" "Serial Communication"
check_tool "screen" "" "Terminal Multiplexer"
check_tool "picocom" "" "Serial Communication"
echo ""

echo -e "${MAGENTA}${BOLD}🎯 Specialized Security Tools${NC}"
echo "================================================"
check_tool "smbmap" "" "SMB Share Enumeration"
check_tool "smbclient" "" "SMB Client"
check_tool "rpcclient" "" "RPC Client"
check_tool "enum4linux" "" "SMB Enumeration"
check_tool "ldapsearch" "" "LDAP Search"
check_tool "snmpwalk" "" "SNMP Scanner"
check_tool "onesixtyone" "" "SNMP Scanner"
check_tool "nbtscan" "" "NetBIOS Scanner"
check_tool "rpcinfo" "" "RPC Service Information"
check_tool "showmount" "" "NFS Mount Information"
check_tool "smtp-user-enum" "" "SMTP User Enumeration"
check_tool "ike-scan" "" "IPsec VPN Scanner"
check_tool "vpnc" "" "Cisco VPN Client"
check_tool "openconnect" "" "Multi-protocol VPN Client"
echo ""

echo -e "${MAGENTA}${BOLD}🎪 CTF & Competition Tools${NC}"
echo "================================================"
check_tool "z3" "" "Theorem Prover"
check_tool "sage" "" "Mathematical Software"
check_tool "gmpy2" "" "Multiple Precision Arithmetic"
check_tool "sympy" "" "Symbolic Mathematics"
check_tool "pycrypto" "" "Cryptographic Library"
check_tool "requests" "" "HTTP Library"
check_tool "beautifulsoup4" "" "Web Scraping"
check_tool "selenium" "" "Browser Automation"
check_tool "pillow" "" "Image Processing"
check_tool "opencv-python" "" "Computer Vision"
check_tool "numpy" "" "Numerical Computing"
check_tool "matplotlib" "" "Plotting Library"
check_tool "capstone" "" "Disassembly Framework"
check_tool "keystone" "" "Assembly Framework"
check_tool "unicorn" "" "CPU Emulator Framework"
echo ""

echo -e "${MAGENTA}${BOLD}🏢 Enterprise Security & Active Directory Tools${NC}"
echo "================================================"
check_tool "sharphound" "" "BloodHound Ingestor"
check_tool "azurehound" "" "Azure Enumeration"
check_tool "powerview" "" "PowerShell AD Enumeration"
check_tool "adrecon" "" "Active Directory Reconnaissance"
check_tool "ldapdomaindump" "" "LDAP Domain Dumper"
check_tool "windapsearch" "" "LDAP Enumeration"
check_tool "rubeus" "" "Kerberos Abuse Toolkit"
check_tool "sprayhound" "" "Password Spraying"
check_tool "kerberoast" "" "Kerberoasting Attack"
check_tool "asreproast" "" "AS-REP Roasting Attack"
check_tool "ntlmrelayx" "" "NTLM Relay Attack"
echo ""

echo -e "${MAGENTA}${BOLD}🎲 System Utilities & Miscellaneous Tools${NC}"
echo "================================================"
check_tool "curl" "" "HTTP Client"
check_tool "wget" "" "Web Content Retriever"
check_tool "jq" "" "JSON Processor"
check_tool "xmllint" "" "XML Processor"
check_tool "base64" "" "Base64 Encoder/Decoder"
check_tool "openssl" "" "Cryptographic Toolkit"
check_tool "gpg" "" "GNU Privacy Guard"
check_tool "ssh" "" "SSH Client"
check_tool "scp" "" "Secure Copy"
check_tool "rsync" "" "File Synchronization"
check_tool "git" "" "Version Control"
check_tool "vim" "" "Text Editor"
check_tool "nano" "" "Text Editor"
check_tool "tmux" "" "Terminal Multiplexer"
check_tool "htop" "" "Process Viewer"
check_tool "iftop" "" "Network Monitor"
check_tool "iotop" "" "I/O Monitor"
check_tool "nethogs" "" "Network Traffic Monitor"
check_tool "lsof" "" "List Open Files"
check_tool "netstat" "" "Network Connections"
check_tool "ss" "" "Socket Statistics"
check_tool "ps" "" "Process Status"
check_tool "grep" "" "Text Search"
check_tool "sed" "" "Stream Editor"
check_tool "awk" "" "Text Processing"
check_tool "find" "" "File Search"
check_tool "locate" "" "File Location"
check_tool "which" "" "Command Location Finder"
check_tool "whereis" "" "Binary Location Finder"
check_tool "man" "" "Manual Pages"
check_tool "info" "" "Info Documents"
echo ""

# Enhanced Summary with detailed statistics
echo "=================================================================="
echo -e "${WHITE}${BOLD}📊 HEXSTRIKE AI COMPREHENSIVE INSTALLATION SUMMARY${NC}"
echo "=================================================================="
echo -e "✅ ${GREEN}${BOLD}Installed tools: $INSTALLED_COUNT/$TOTAL_COUNT${NC}"
echo -e "❌ ${RED}${BOLD}Missing tools: $MISSING_COUNT/$TOTAL_COUNT${NC}"

# Calculate coverage percentage
PERCENTAGE=$(( (INSTALLED_COUNT * 100) / TOTAL_COUNT ))

# Enhanced category analysis
echo ""
echo -e "${CYAN}📋 TOOL COVERAGE ANALYSIS:${NC}"

# Count tools by category
declare -A CATEGORY_INSTALLED
declare -A CATEGORY_TOTAL

for tool in "${INSTALLED_TOOLS[@]}"; do
   CATEGORY_INSTALLED["Installed"]=$((${CATEGORY_INSTALLED["Installed"]} + 1))
done

for missing in "${MISSING_TOOLS[@]}"; do
   local category=$(echo "$missing" | cut -d':' -f3)
   CATEGORY_TOTAL["$category"]=$((${CATEGORY_TOTAL["$category"]} + 1))
done

# Display category breakdown
echo -e "${BLUE}Missing tools by category:${NC}"
for category in "${!CATEGORY_TOTAL[@]}"; do
   if [ "${CATEGORY_TOTAL[$category]}" -gt 0 ]; then
       echo -e "  ${YELLOW}$category${NC}: ${CATEGORY_TOTAL[$category]} tools missing"
   fi
done

echo ""
echo -e "${BLUE}🤖 AI AGENT COMPATIBILITY STATUS:${NC}"
if [ $MISSING_COUNT -eq 0 ]; then
   echo -e "✅ ${GREEN}${BOLD}PERFECT! All 150+ tools ready for AI agent automation${NC}"
   echo -e "${GREEN}🚀 HexStrike AI can perform comprehensive autonomous cybersecurity assessments${NC}"
elif [ $MISSING_COUNT -le 10 ]; then
   echo -e "👍 ${GREEN}EXCELLENT! Most tools available - AI agents can perform comprehensive assessments${NC}"
   echo -e "${GREEN}✅ HexStrike AI has nearly full functionality${NC}"
elif [ $MISSING_COUNT -le 25 ]; then
   echo -e "👌 ${YELLOW}GOOD! Solid tool coverage - AI agents can perform most security tasks${NC}"
   echo -e "${YELLOW}⚠️  Some specialized features may be limited${NC}"
elif [ $MISSING_COUNT -le 50 ]; then
   echo -e "⚠️  ${ORANGE}MODERATE! Basic AI agent security testing possible${NC}"
   echo -e "${ORANGE}❌ Some advanced HexStrike AI features unavailable${NC}"
else
   echo -e "❌ ${RED}INSUFFICIENT! Major limitations in AI agent capabilities${NC}"
   echo -e "${RED}🔧 Install more tools for meaningful HexStrike AI functionality${NC}"
fi

# Essential tools analysis (ENHANCED)
echo ""
echo -e "${CYAN}📋 HEXSTRIKE AI OFFICIAL REQUIREMENTS:${NC}"
echo "================================================"

# Expanded essential tools based on categories
ESSENTIAL_TOOLS=("nmap" "nuclei" "amass" "subfinder" "gobuster" "ffuf" "sqlmap" "hydra" "john" "hashcat" "gdb" "radare2" "volatility3" "metasploit-framework" "burpsuite" "wireshark" "aircrack-ng" "impacket" "bloodhound" "responder")
ESSENTIAL_MISSING=0
ESSENTIAL_TOTAL=${#ESSENTIAL_TOOLS[@]}

echo -e "${YELLOW}🔥 Essential Tools Status (Top 20):${NC}"
for tool in "${ESSENTIAL_TOOLS[@]}"; do
   if command -v "$tool" > /dev/null 2>&1 || command -v "${tool/metasploit-framework/msfconsole}" > /dev/null 2>&1; then
       echo -e "  ✅ ${GREEN}$tool${NC}"
   else
       echo -e "  ❌ ${RED}$tool${NC} - CRITICAL"
       ESSENTIAL_MISSING=$((ESSENTIAL_MISSING + 1))
   fi
done

echo ""
if [ $ESSENTIAL_MISSING -eq 0 ]; then
   echo -e "🎉 ${GREEN}${BOLD}All essential HexStrike AI tools are installed!${NC}"
   echo -e "${GREEN}🚀 Ready for advanced autonomous penetration testing!${NC}"
elif [ $ESSENTIAL_MISSING -le 5 ]; then
   echo -e "👍 ${YELLOW}Most essential tools installed. Minor gaps detected.${NC}"
   echo -e "${YELLOW}⚠️  Install remaining $ESSENTIAL_MISSING tools for full functionality${NC}"
else
   echo -e "⚠️  ${RED}$ESSENTIAL_MISSING/$ESSENTIAL_TOTAL essential tools missing. HexStrike AI functionality will be significantly limited.${NC}"
   echo -e "${RED}🔧 Priority installation required for core capabilities${NC}"
fi

# Performance indicator with enhanced HexStrike AI context
echo ""
echo -e "${WHITE}${BOLD}📈 HEXSTRIKE AI READINESS SCORE: $PERCENTAGE%${NC}"

# Enhanced scoring system
if [ $PERCENTAGE -ge 95 ]; then
   echo -e "🔥 ${GREEN}${BOLD}LEGENDARY SETUP! Your AI agents are ready for elite autonomous pentesting!${NC}"
   echo -e "${GREEN}✅ Complete HexStrike AI arsenal unlocked - All 150+ tools available${NC}"
   echo -e "${GREEN}🎯 Capable of: Advanced persistent threats simulation, zero-day research, nation-state level assessments${NC}"
elif [ $PERCENTAGE -ge 90 ]; then
   echo -e "🚀 ${GREEN}${BOLD}ELITE SETUP! Your AI agents are ready for advanced autonomous pentesting!${NC}"
   echo -e "${GREEN}✅ Full HexStrike AI capabilities unlocked${NC}"
   echo -e "${GREEN}🎯 Capable of: Enterprise-level assessments, advanced threat modeling, comprehensive security audits${NC}"
elif [ $PERCENTAGE -ge 80 ]; then
   echo -e "🚀 ${GREEN}EXCELLENT! AI agents can perform comprehensive security assessments${NC}"
   echo -e "${GREEN}✅ Most HexStrike AI features available${NC}"
   echo -e "${GREEN}🎯 Capable of: Professional penetration testing, vulnerability assessments, compliance auditing${NC}"
elif [ $PERCENTAGE -ge 70 ]; then
   echo -e "👍 ${YELLOW}GOOD! AI agents have solid cybersecurity capabilities${NC}"
   echo -e "${YELLOW}⚠️  Some advanced features may be limited${NC}"
   echo -e "${YELLOW}🎯 Capable of: Basic penetration testing, network scanning, web application testing${NC}"
elif [ $PERCENTAGE -ge 50 ]; then
   echo -e "⚠️  ${ORANGE}MODERATE! Basic AI agent security testing possible${NC}"
   echo -e "${ORANGE}❌ Advanced HexStrike AI features unavailable${NC}"
   echo -e "${ORANGE}🎯 Capable of: Basic vulnerability scanning, simple reconnaissance, limited assessments${NC}"
else
   echo -e "❌ ${RED}INSUFFICIENT! Major limitations in AI agent capabilities${NC}"
   echo -e "${RED}🔧 Install more tools for meaningful HexStrike AI functionality${NC}"
   echo -e "${RED}🎯 Current capability: Very limited security testing, basic scanning only${NC}"
fi

# Installation commands generation
if [ $MISSING_COUNT -gt 0 ]; then
   echo ""
   generate_verified_install_commands
fi

# Enhanced next steps and resources
echo ""
echo -e "${BLUE}${BOLD}💡 COMPLETE HEXSTRIKE AI DEPLOYMENT GUIDE:${NC}"
echo "=================================================================="
echo ""
echo -e "${GREEN}🔥 Step 1: Install Missing Tools${NC}"
echo "   Use the installation commands generated above"
echo ""
echo -e "${GREEN}🔥 Step 2: Clone HexStrike AI Repository${NC}"
echo "   git clone https://github.com/0x4m4/hexstrike-ai.git"
echo "   cd hexstrike-ai"
echo ""
echo -e "${GREEN}🔥 Step 3: Install Python Dependencies${NC}"
echo "   pip3 install -r requirements.txt"
echo "   pip3 install anthropic openai langchain"
echo ""
echo -e "${GREEN}🔥 Step 4: Set Up Environment${NC}"
echo "   export ANTHROPIC_API_KEY='your_api_key_here'"
echo "   export OPENAI_API_KEY='your_openai_key_here'"
echo ""
echo -e "${GREEN}🔥 Step 5: Configure Tools Directory${NC}"
echo "   mkdir -p ~/tools/{wordlists,scripts,exploits,payloads,results}"
echo "   export HEXSTRIKE_TOOLS_DIR=~/tools"
echo ""
echo -e "${GREEN}🔥 Step 6: Download Essential Wordlists & Databases${NC}"
echo "   cd ~/tools/wordlists"
echo "   git clone https://github.com/danielmiessler/SecLists.git"
echo "   wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
echo "   git clone https://github.com/berzerk0/Probable-Wordlists.git"
echo ""
echo -e "${GREEN}🔥 Step 7: Update Nuclei Templates${NC}"
echo "   nuclei -update-templates -silent"
echo ""
echo -e "${GREEN}🔥 Step 8: Start HexStrike AI Server${NC}"
echo "   python3 hexstrike_server.py --port 8080 --host 0.0.0.0"
echo ""
echo -e "${GREEN}🔥 Step 9: Configure Your AI Agent${NC}"
echo "   Install MCP client and connect to HexStrike AI server"
echo "   Configure Claude/GPT with HexStrike AI MCP integration"
echo ""
echo -e "${GREEN}🔥 Step 10: Test Installation${NC}"
echo "   python3 test_installation.py"
echo "   curl http://localhost:8080/health"
echo ""

# Advanced configuration section
echo -e "${BLUE}${BOLD}🛠️  ADVANCED CONFIGURATION OPTIONS:${NC}"
echo "=================================================================="
echo ""
echo -e "${CYAN}🔧 Custom Tool Paths:${NC}"
echo "   export HEXSTRIKE_NMAP_PATH=/usr/bin/nmap"
echo "   export HEXSTRIKE_NUCLEI_PATH=\$HOME/go/bin/nuclei"
echo "   export HEXSTRIKE_BURP_PATH=/opt/burpsuite/burpsuite_community.jar"
echo ""
echo -e "${CYAN}🔧 Performance Tuning:${NC}"
echo "   export HEXSTRIKE_MAX_THREADS=50"
echo "   export HEXSTRIKE_TIMEOUT=300"
echo "   export HEXSTRIKE_MAX_TARGETS=1000"
echo ""
echo -e "${CYAN}🔧 Output Configuration:${NC}"
echo "   export HEXSTRIKE_OUTPUT_DIR=~/tools/results"
echo "   export HEXSTRIKE_LOG_LEVEL=INFO"
echo "   export HEXSTRIKE_REPORT_FORMAT=json,html,pdf"
echo ""
echo -e "${CYAN}🔧 AI Model Configuration:${NC}"
echo "   export HEXSTRIKE_AI_MODEL=claude-3-sonnet-20240229"
echo "   export HEXSTRIKE_AI_TEMPERATURE=0.2"
echo "   export HEXSTRIKE_AI_MAX_TOKENS=4096"
echo ""

# Resource links section
echo -e "${CYAN}${BOLD}🌐 OFFICIAL HEXSTRIKE AI RESOURCES & COMMUNITY:${NC}"
echo "=================================================================="
echo -e "${BLUE}📖 Documentation & Guides:${NC}"
echo "   • Main Repository: https://github.com/0x4m4/hexstrike-ai"
echo "   • Installation Guide: https://github.com/0x4m4/hexstrike-ai/blob/master/INSTALL.md"
echo "   • API Documentation: https://github.com/0x4m4/hexstrike-ai/blob/master/API.md"
echo ""
echo -e "${BLUE}🌍 Official Websites & Platforms:${NC}"
echo "   • HexStrike Official: https://www.hexstrike.com"
echo "   • Author's Website: https://www.0x4m4.com"
echo "   • Blog : https://blog.hexstrike.com"
echo "   • Linkedin : https://www.linkedin.com/company/hexstrike-ai"
echo -e "${BLUE}🤝 Community & Support:${NC}"
echo "   • Discord Server: https://discord.gg/KsYJBBT3"
echo "   • Twitter: @HexStrikeAI"
echo "   • YouTube Channel: HexStrike AI Security"
echo ""

# Final motivation message
echo -e "${GREEN}${BOLD}🎯 MISSION ACCOMPLISHED CHECKLIST:${NC}"
echo "=================================================================="
echo -e "${GREEN}□ Install missing tools using generated commands${NC}"
echo -e "${GREEN}□ Clone HexStrike AI repository${NC}"
echo -e "${GREEN}□ Configure environment variables${NC}"
echo -e "${GREEN}□ Set up wordlists and databases${NC}"
echo -e "${GREEN}□ Test tool functionality${NC}"
echo -e "${GREEN}□ Configure AI agent integration${NC}"
echo -e "${GREEN}□ Run initial security assessment${NC}"
echo -e "${GREEN}□ Join HexStrike community${NC}"
echo ""
echo -e "${WHITE}${BOLD}🤖 READY TO EMPOWER YOUR AI AGENTS WITH AUTONOMOUS CYBERSECURITY CAPABILITIES!${NC}"
echo ""
echo -e "${CYAN}Remember: With great power comes great responsibility.${NC}"
echo -e "${CYAN}Use HexStrike AI ethically and only on systems you own or have explicit permission to test.${NC}"
echo ""
echo -e "${PURPLE}${BOLD}Happy Hacking! 🚀💀🔥${NC}"
echo ""
