#!/bin/bash

# HexStrike AI - Tools Verification Script (V6 Complete Edition)
# Based on Official HexStrike-Ai V6 README - 200+ tools coverage
# Version 6.0 - Complete V6 alignment with all missing tools added

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    FUTURISTIC COLOR & EFFECTS SYSTEM                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# Advanced Color Palette - Cyberpunk Theme
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
ORANGE='\033[0;33m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Neon Colors - Futuristic Glow Effect
NEON_GREEN='\033[38;5;46m'
NEON_BLUE='\033[38;5;51m'
NEON_PINK='\033[38;5;201m'
NEON_PURPLE='\033[38;5;129m'
NEON_ORANGE='\033[38;5;208m'
NEON_YELLOW='\033[38;5;226m'
ELECTRIC_BLUE='\033[38;5;27m'
MATRIX_GREEN='\033[38;5;40m'
CYBER_CYAN='\033[38;5;87m'
PLASMA_PURPLE='\033[38;5;93m'

# Gradient Colors
GRAD_RED1='\033[38;5;196m'
GRAD_RED2='\033[38;5;160m'
GRAD_RED3='\033[38;5;124m'
GRAD_BLUE1='\033[38;5;21m'
GRAD_BLUE2='\033[38;5;20m'
GRAD_BLUE3='\033[38;5;19m'
GRAD_GREEN1='\033[38;5;46m'
GRAD_GREEN2='\033[38;5;40m'
GRAD_GREEN3='\033[38;5;34m'

# Text Styles & Effects
BOLD='\033[1m'
DIM='\033[2m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
STRIKETHROUGH='\033[9m'
DOUBLE_UNDERLINE='\033[21m'

# Background Colors with Gradient Effect
BG_BLACK='\033[40m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'
BG_MAGENTA='\033[45m'
BG_CYAN='\033[46m'
BG_WHITE='\033[47m'
BG_NEON_BLUE='\033[48;5;21m'
BG_NEON_GREEN='\033[48;5;46m'
BG_DARK_GRAY='\033[48;5;236m'

# Futuristic Status Icons & Symbols
CHECK_MARK="${NEON_GREEN}◉${NC}"
CROSS_MARK="${NEON_PINK}◎${NC}"
INFO_ICON="${ELECTRIC_BLUE}◈${NC}"
WARNING_ICON="${NEON_YELLOW}◆${NC}"
GEAR_ICON="${CYBER_CYAN}◇${NC}"
SEARCH_ICON="${PLASMA_PURPLE}◐${NC}"
LOADING_ICON="${NEON_BLUE}◑${NC}"
SUCCESS_ICON="${MATRIX_GREEN}◒${NC}"
ERROR_ICON="${GRAD_RED1}◓${NC}"
PROGRESS_ICON="${NEON_ORANGE}◔${NC}"

# Advanced Unicode Box Drawing & Effects
BOX_H="═"
BOX_V="║"
BOX_TL="╔"
BOX_TR="╗"
BOX_BL="╚"
BOX_BR="╝"
BOX_CROSS="╬"
BOX_T="╦"
BOX_B="╩"
BOX_L="╠"
BOX_R="╣"

# Double Line Box Drawing
DBOX_H="═"
DBOX_V="║"
DBOX_TL="╔"
DBOX_TR="╗"
DBOX_BL="╚"
DBOX_BR="╝"

# Progress Bar Characters - Futuristic Style
PROGRESS_FULL="█"
PROGRESS_PARTIAL="▓"
PROGRESS_LIGHT="▒"
PROGRESS_EMPTY="░"
PROGRESS_GLOW="▬"
PROGRESS_SPARK="◆"

# Animated Characters for Loading
SPINNER_CHARS=("◐" "◓" "◑" "◒")
PULSE_CHARS=("●" "◉" "○" "◯")
WAVE_CHARS=("▁" "▂" "▃" "▄" "▅" "▆" "▇" "█")

# Matrix Rain Effect Characters
MATRIX_CHARS=("0" "1" "ア" "カ" "サ" "タ" "ナ" "ハ" "マ" "ヤ" "ラ" "ワ")

# Hologram Effect Function
hologram_text() {
    local text="$1"
    local color1="$2"
    local color2="$3"
    echo -e "${color1}${BOLD}${text}${NC}${color2}▓${NC}"
}

# Glitch Effect Function
glitch_text() {
    local text="$1"
    echo -e "${NEON_PINK}${text}${NC}${REVERSE} ${NC}${NEON_BLUE}${text}${NC}"
}

# Neon Glow Effect Function
neon_glow() {
    local text="$1"
    local color="$2"
    echo -e "${color}${BOLD}▓▓${NC} ${color}${BOLD}${text}${NC} ${color}${BOLD}▓▓${NC}"
}

# Cyberpunk Border Function
cyber_border() {
    local width="$1"
    local color="$2"
    printf "${color}${BOLD}"
    printf "▓"
    for ((i=1; i<width-1; i++)); do
        printf "▀"
    done
    printf "▓${NC}\n"
}

# Futuristic Category Header with Cyberpunk Effects
show_category_header() {
    local category="$1"
    local icon="$2"
    
    # Animated separator
    echo -e "\n${CYBER_CYAN}${BOLD}"
    printf "    ◆"
    for i in {1..70}; do
        printf "▬"
    done
    printf "◆${NC}\n"
    
    # Holographic category display with neon glow
    echo -e "${NEON_BLUE}${BOLD}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${NEON_BLUE}║${NC} ${BG_NEON_BLUE}${WHITE}${BOLD}  ${icon} ${category} - NEURAL SCAN INITIATED  ${NC} ${NEON_BLUE}║${NC}"
    echo -e "${NEON_BLUE}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # Matrix-style loading effect
    printf "${MATRIX_GREEN}    "
    for i in {1..3}; do
        printf "${SPINNER_CHARS[$((i % 4))]}"
        sleep 0.1
    done
    printf " ${NEON_GREEN}${BOLD}SCANNING...${NC}\n"
}

# Initialize counters
INSTALLED_COUNT=0
MISSING_COUNT=0
TOTAL_COUNT=0

# Arrays to store tool information
MISSING_TOOLS=()
INSTALLED_TOOLS=()

# Tool categorization arrays for package managers
APT_TOOLS=("nmap" "masscan" "gobuster" "ffuf" "dirb" "dirbuster" "wfuzz" "feroxbuster" "dirsearch" "whatweb" "wafw00f" "eyewitness" "sqlmap" "wpscan" "zaproxy" "arjun" "nikto" "uniscan" "skipfish" "w3af" "commix" "xsser" "sqlninja" "jsql-injection" "wapiti" "cadaver" "davtest" "padbuster" "joomscan" "droopescan" "cmsmap" "nosqlmap" "tplmap" "hydra" "john" "hashcat" "medusa" "patator" "crackmapexec" "ncrack" "crowbar" "brutespray" "thc-hydra" "ophcrack" "rainbowcrack" "hashcat-utils" "pack" "kwprocessor" "hash-identifier" "hashid" "crackstation" "gdb" "radare2" "binwalk" "checksec" "strings" "objdump" "xxd" "hexdump" "ropper" "ropgadget" "upx" "readelf" "volatility3" "autopsy" "bulk-extractor" "scalpel" "testdisk" "dc3dd" "ddrescue" "foremost" "photorec" "sleuthkit" "afflib-tools" "libewf-tools" "steghide" "stegsolve" "zsteg" "outguess" "exiftool" "aircrack-ng" "reaver" "wifite" "kismet" "wireshark" "tshark" "tcpdump" "ettercap" "bettercap" "hostapd" "dnsmasq" "macchanger" "mdk3" "mdk4" "pixiewps" "aapt" "adb" "fastboot" "usbmuxd" "libimobiledevice-utils" "apktool" "dex2jar" "jd-gui" "jadx" "frida" "objection" "drozer" "metasploit-framework" "msfvenom" "msfconsole" "searchsploit" "exploit-db" "beef-xss" "armitage" "responder" "impacket" "theharvester" "recon-ng" "maltego" "spiderfoot" "fierce" "dnsrecon" "dnsenum" "dmitry" "sherlock" "linpeas" "winpeas" "linenum" "linux-exploit-suggester" "windows-exploit-suggester" "privesc-check" "unix-privesc-check" "gtfoblookup" "docker" "docker.io" "kubectl" "helm" "curl" "wget" "git" "vim" "nano" "tmux" "screen" "htop" "iotop" "netstat" "ss" "lsof" "strace" "ltrace" "ncat" "socat" "netcat" "enum4linux" "enum4linux-ng" "smbmap" "netexec" "testssl" "sslscan" "sslyze" "sublist3r" "knockpy" "awscli" "google-cloud-sdk" "trivy" "falco")

SNAP_TOOLS=("amass" "bloodhound" "code" "ghidra" "ida-free" "cutter" "binary-ninja")

PIP_TOOLS=("shodan" "censys" "social-analyzer" "have-i-been-pwned" "trufflehog" "subjack" "cloudsplaining" "pacu" "prowler" "scout-suite" "cloudmapper" "checkov" "terrascan" "cloudsploit" "pwntools" "one-gadget" "angr" "pwninit" "autorecon" "jwt-tool" "graphql-voyager" "peda" "gef" "pwngdb" "voltron" "gdb-peda" "gdb-gef" "libc-database" "cipher-identifier" "frequency-analysis" "rsatool" "factordb" "hashcat-legacy" "hash-buster" "findmyhash" "hash-analyzer")

GEM_TOOLS=("wpscan")

GO_TOOLS=("rustscan" "naabu" "assetfinder" "subfinder" "nuclei" "httpx" "katana" "hakrawler" "gau" "paramspider" "x8" "jaeles" "dalfox" "anew" "qsreplace" "uro" "waybackurls" "httprobe" "gowitness" "aquatone" "kube-hunter" "kube-bench")

CUSTOM_TOOLS=("cobalt-strike" "empire" "powersploit" "mimikatz" "powerview" "ida-free" "cutter" "binary-ninja" "angr" "libc-database" "pwninit" "cyberchef" "stegsolve" "zsteg" "one-gadget" "peda" "gef" "pwngdb" "voltron" "pwntools" "aws-cli" "azure-cli" "gcloud" "clair" "docker-bench-security" "istio" "opa" "volatility" "msfvenom-cloud" "cloudgoat" "cipher-identifier" "frequency-analysis" "rsatool" "factordb" "hashcat-legacy" "hash-buster" "findmyhash" "hash-analyzer")

# Check if curl is available
CURL_AVAILABLE=false
if command -v curl > /dev/null 2>&1; then
    CURL_AVAILABLE=true
fi

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
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH_TYPE="amd64" ;;
        aarch64|arm64) ARCH_TYPE="arm64" ;;
        armv7l) ARCH_TYPE="armv7" ;;
        i686|i386) ARCH_TYPE="i386" ;;
        *) ARCH_TYPE="amd64" ;;
    esac
}

# Get package manager
get_package_manager() {
    case $DISTRO in
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            PKG_MANAGER="apt"
            INSTALL_CMD="sudo apt update && sudo apt install -y"
            ;;
        "fedora"|"rhel"|"centos")
            if command -v dnf > /dev/null 2>&1; then
                PKG_MANAGER="dnf"
                INSTALL_CMD="sudo dnf install -y"
            else
                PKG_MANAGER="yum"
                INSTALL_CMD="sudo yum install -y"
            fi
            ;;
        "arch"|"manjaro"|"endeavouros")
            PKG_MANAGER="pacman"
            INSTALL_CMD="sudo pacman -S"
            ;;
        "opensuse"|"opensuse-leap"|"opensuse-tumbleweed")
            PKG_MANAGER="zypper"
            INSTALL_CMD="sudo zypper install -y"
            ;;
        "alpine")
            PKG_MANAGER="apk"
            INSTALL_CMD="sudo apk add"
            ;;
        *)
            PKG_MANAGER="unknown"
            INSTALL_CMD="# Unknown package manager"
            ;;
    esac
}

# Enhanced tool checking function
check_tool() {
    local tool=$1
    local alt_check=$2
    local category=${3:-"General"}
    
    # Check primary command
    if command -v "$tool" > /dev/null 2>&1; then
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi
    
    # Check alternative command
    if [ -n "$alt_check" ] && command -v "$alt_check" > /dev/null 2>&1; then
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi
    
    # Check Python package
    if python3 -c "import $tool" > /dev/null 2>&1; then
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi
    
    # Check common locations
    local locations=(
        "/usr/bin/$tool" "/usr/local/bin/$tool" "/opt/$tool"
        "/home/$USER/tools/$tool" "/home/$USER/Desktop/$tool"
        "/usr/share/$tool" "/snap/bin/$tool" "/usr/local/share/$tool"
        "/var/lib/gems/*/bin/$tool" "/usr/local/go/bin/$tool"
        "$HOME/go/bin/$tool" "$HOME/.cargo/bin/$tool" "$HOME/.local/bin/$tool"
        "/usr/local/sbin/$tool" "/sbin/$tool" "/usr/sbin/$tool"
    )
    
    for location in "${locations[@]}"; do
        if [ -f "$location" ] || [ -d "$location" ]; then
            INSTALLED_TOOLS+=("$tool")
            INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
            return 0
        fi
    done
    
    # Tool not found
    MISSING_TOOLS+=("$tool:$category")
    MISSING_COUNT=$((MISSING_COUNT + 1))
    return 1
}

# Futuristic Animated Banner with Cyberpunk Effects
show_banner() {
    clear
    
    # Matrix rain effect simulation
    echo -e "${MATRIX_GREEN}${DIM}"
    for i in {1..3}; do
        printf "    "
        for j in {1..70}; do
            printf "${MATRIX_CHARS[$((RANDOM % ${#MATRIX_CHARS[@]}))]}"
        done
        echo
        sleep 0.05
    done
    echo -e "${NC}"
    
    # Main cyberpunk banner with neon effects
    echo -e "${NEON_BLUE}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo -e "║ ${NEON_PINK}▓▓▓${NC} ${ELECTRIC_BLUE}${BOLD}██╗  ██╗███████╗██╗  ██╗${NEON_ORANGE}███████╗████████╗██████╗ ██╗██╗  ██╗███████╗${NC} ${NEON_PINK}▓▓▓${NC} ${NEON_BLUE}║${NC}"
    echo -e "║ ${NEON_PINK}▓▓▓${NC} ${ELECTRIC_BLUE}${BOLD}██║  ██║██╔════╝╚██╗██╔╝${NEON_ORANGE}██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝${NC} ${NEON_PINK}▓▓▓${NC} ${NEON_BLUE}║${NC}"
    echo -e "║ ${NEON_PINK}▓▓▓${NC} ${ELECTRIC_BLUE}${BOLD}███████║█████╗   ╚███╔╝ ${NEON_ORANGE}███████╗   ██║   ██████╔╝██║█████╔╝ █████╗${NC}   ${NEON_PINK}▓▓▓${NC} ${NEON_BLUE}║${NC}"
    echo -e "║ ${NEON_PINK}▓▓▓${NC} ${ELECTRIC_BLUE}${BOLD}██╔══██║██╔══╝   ██╔██╗ ${NEON_ORANGE}╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝${NC}   ${NEON_PINK}▓▓▓${NC} ${NEON_BLUE}║${NC}"
    echo -e "║ ${NEON_PINK}▓▓▓${NC} ${ELECTRIC_BLUE}${BOLD}██║  ██║███████╗██╔╝ ██╗${NEON_ORANGE}███████║   ██║   ██║  ██║██║██║  ██╗███████╗${NC} ${NEON_PINK}▓▓▓${NC} ${NEON_BLUE}║${NC}"
    echo -e "║ ${NEON_PINK}▓▓▓${NC} ${ELECTRIC_BLUE}${BOLD}╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝${NEON_ORANGE}╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝${NC} ${NEON_PINK}▓▓▓${NC} ${NEON_BLUE}║${NC}"
    echo -e "║${PLASMA_PURPLE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}${NEON_BLUE}║${NC}"
    echo -e "║                    ${NEON_YELLOW}${BOLD}🤖 AI TOOLS CHECKER v6.0 - CYBERPUNK EDITION${NC}                    ${NEON_BLUE}║${NC}"
    echo -e "║              ${CYBER_CYAN}${BOLD}◆◇◆ COMPREHENSIVE SECURITY TOOLS VERIFICATION ◆◇◆${NC}               ${NEON_BLUE}║${NC}"
    echo -e "║${PLASMA_PURPLE}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓${NC}${NEON_BLUE}║${NC}"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Animated loading bar
    echo -e "${NEON_BLUE}${BOLD}    ◆◇◆ INITIALIZING CYBERSECURITY MATRIX ◆◇◆${NC}"
    printf "${CYBER_CYAN}    ["
    for i in {1..50}; do
        printf "${PROGRESS_GLOW}"
        sleep 0.02
    done
    printf "]${NC}\n\n"
    
    # Holographic system information panel
    echo -e "${NEON_PINK}${BOLD}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${NEON_PINK}║${NC} ${BG_DARK_GRAY}${NEON_GREEN}${BOLD}    🔮 SYSTEM NEURAL INTERFACE - QUANTUM ANALYSIS PROTOCOL    ${NC} ${NEON_PINK}║${NC}"
    echo -e "${NEON_PINK}╠═══════════════════════════════════════════════════════════════════════════════╣${NC}"
    
    # Animated system info with holographic effects
    echo -e "${NEON_PINK}║${NC} ${ELECTRIC_BLUE}◈${NC} ${NEON_YELLOW}DISTRO_MATRIX:${NC} ${MATRIX_GREEN}${BOLD}$PRETTY_NAME${NC}${NEON_BLUE}▓${NC} ${NEON_PINK}║${NC}"
    echo -e "${NEON_PINK}║${NC} ${ELECTRIC_BLUE}◈${NC} ${NEON_YELLOW}ARCH_PROTOCOL:${NC} ${NEON_ORANGE}${BOLD}$ARCH ($ARCH_TYPE)${NC}${CYBER_CYAN}▓${NC} ${NEON_PINK}║${NC}"
    echo -e "${NEON_PINK}║${NC} ${ELECTRIC_BLUE}◈${NC} ${NEON_YELLOW}PKG_HANDLER:${NC} ${PLASMA_PURPLE}${BOLD}$PACKAGE_MANAGER${NC}${NEON_GREEN}▓${NC} ${NEON_PINK}║${NC}"
    echo -e "${NEON_PINK}║${NC} ${ELECTRIC_BLUE}◈${NC} ${NEON_YELLOW}TEMPORAL_SYNC:${NC} ${NEON_BLUE}${BOLD}$(date +'%Y-%m-%d %H:%M:%S')${NC}${NEON_PINK}▓${NC} ${NEON_PINK}║${NC}"
    
    echo -e "${NEON_PINK}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
    
    # Cyberpunk separator with animated effect
    echo -e "\n${CYBER_CYAN}${BOLD}"
    printf "    ◆"
    for i in {1..70}; do
        printf "▬"
    done
    printf "◆${NC}\n"
    
    # Status indicators with pulse effect
    echo -e "    ${SUCCESS_ICON} ${NEON_GREEN}NEURAL_NETWORK: ${BOLD}ONLINE${NC}    ${PROGRESS_ICON} ${NEON_ORANGE}SCANNING_MODE: ${BOLD}ACTIVE${NC}    ${INFO_ICON} ${ELECTRIC_BLUE}AI_CORE: ${BOLD}READY${NC}\n"
}

# Display system information
show_system_info() {
    echo -e "${CYAN}${BOLD}📋 SYSTEM INFORMATION${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}🐧 Operating System:${NC} ${WHITE}$PRETTY_NAME${NC}"
    echo -e "${BLUE}📦 Distribution:${NC}     ${WHITE}$DISTRO${NC}"
    echo -e "${BLUE}🗂️  Architecture:${NC}    ${WHITE}$ARCH ($ARCH_TYPE)${NC}"
    echo -e "${BLUE}📦 Package Manager:${NC}  ${WHITE}$PKG_MANAGER${NC}"
    echo ""
}

# Calculate total number of tools (EXPANDED LIST - V6 COMPLETE)
calculate_total_tools() {
    # Network Reconnaissance & Scanning (47 tools - expanded from 25)
    local network_tools=("nmap" "amass" "subfinder" "nuclei" "masscan" "rustscan" "naabu" "httpx" "assetfinder" "sublist3r" "knockpy" "gobuster" "ffuf" "dirb" "dirbuster" "wfuzz" "feroxbuster" "dirsearch" "whatweb" "wafw00f" "eyewitness" "aquatone" "gowitness" "httprobe" "waybackurls" "autorecon" "arp-scan" "nbtscan" "rpcclient" "enum4linux" "enum4linux-ng" "smbmap" "netexec" "katana" "hakrawler" "gau" "paramspider" "x8" "jaeles" "dalfox" "testssl" "sslscan" "sslyze" "anew" "qsreplace" "uro" "jwt-tool")
    
    # Web Application Security (23 tools - expanded from 20)
    local web_tools=("sqlmap" "wpscan" "zaproxy" "arjun" "nikto" "uniscan" "skipfish" "w3af" "burpsuite" "commix" "xsser" "sqlninja" "jsql-injection" "wapiti" "cadaver" "davtest" "padbuster" "joomscan" "droopescan" "cmsmap" "nosqlmap" "tplmap" "graphql-voyager")
    
    # Password & Authentication (18 tools - expanded from 15)
    local auth_tools=("hydra" "john" "hashcat" "medusa" "patator" "crackmapexec" "ncrack" "crowbar" "brutespray" "thc-hydra" "ophcrack" "rainbowcrack" "hashcat-utils" "pack" "kwprocessor" "hash-identifier" "hashid" "crackstation")
    
    # Binary Analysis & Reverse Engineering (28 tools - expanded from 18)
    local binary_tools=("gdb" "radare2" "binwalk" "checksec" "strings" "objdump" "xxd" "hexdump" "ghidra" "ida-free" "cutter" "pwntools" "ropper" "one-gadget" "peda" "gef" "pwngdb" "voltron" "gdb-peda" "gdb-gef" "binary-ninja" "ropgadget" "angr" "libc-database" "pwninit" "upx" "readelf" "cyberchef")
    
    # Forensics & Analysis (17 tools - expanded from 12)
    local forensics_tools=("volatility3" "autopsy" "bulk-extractor" "scalpel" "testdisk" "dc3dd" "ddrescue" "foremost" "photorec" "sleuthkit" "afflib-tools" "libewf-tools" "steghide" "stegsolve" "zsteg" "outguess" "exiftool")
    
    # Wireless & Network Security (15 tools - unchanged)
    local wireless_tools=("aircrack-ng" "reaver" "wifite" "kismet" "wireshark" "tshark" "tcpdump" "ettercap" "bettercap" "hostapd" "dnsmasq" "macchanger" "mdk3" "mdk4" "pixiewps")
    
    # Mobile & Hardware Security (13 tools - expanded from 12)
    local mobile_tools=("aapt" "adb" "fastboot" "usbmuxd" "libimobiledevice-utils" "apktool" "dex2jar" "jd-gui" "jadx" "frida" "objection" "drozer" "evil-winrm")
    
    # Exploitation Tools (15 tools - unchanged)
    local exploit_tools=("metasploit-framework" "msfvenom" "msfconsole" "searchsploit" "exploit-db" "beef-xss" "armitage" "cobalt-strike" "empire" "powersploit" "mimikatz" "responder" "impacket" "bloodhound" "powerview")
    
    # Information Gathering (16 tools - expanded from 10)
    local osint_tools=("theHarvester" "recon-ng" "maltego" "spiderfoot" "shodan" "censys-python" "fierce" "dnsrecon" "dnsenum" "dmitry" "sherlock" "social-analyzer" "pipl" "trufflehog" "have-i-been-pwned" "subjack")
    
    # Post-Exploitation (8 tools - unchanged)
    local post_exploit_tools=("linpeas" "winpeas" "linenum" "linux-exploit-suggester" "windows-exploit-suggester" "privesc-check" "unix-privesc-check" "gtfoblookup")
    
    # Cloud Security (25 tools - expanded from 8)
    local cloud_tools=("aws-cli" "azure-cli" "gcloud" "kubectl" "docker" "trivy" "cloudsplaining" "pacu" "prowler" "scout-suite" "cloudmapper" "clair" "kube-hunter" "kube-bench" "docker-bench-security" "falco" "checkov" "terrascan" "cloudsploit" "helm" "istio" "opa" "volatility" "msfvenom-cloud" "cloudgoat")
    
    # Cryptography & Hash Analysis (8 tools - new category)
    local crypto_tools=("cipher-identifier" "frequency-analysis" "rsatool" "factordb" "hashcat-legacy" "hash-buster" "findmyhash" "hash-analyzer")
    
    # System Utilities (12 tools - unchanged)
    local system_tools=("tmux" "screen" "htop" "iotop" "netstat" "ss" "lsof" "strace" "ltrace" "gdb" "ncat" "socat")
    
    # Calculate total count
    TOTAL_COUNT=$((
        ${#network_tools[@]} + 
        ${#web_tools[@]} + 
        ${#auth_tools[@]} + 
        ${#binary_tools[@]} + 
        ${#forensics_tools[@]} + 
        ${#wireless_tools[@]} + 
        ${#mobile_tools[@]} + 
        ${#exploit_tools[@]} + 
        ${#osint_tools[@]} + 
        ${#post_exploit_tools[@]} + 
        ${#cloud_tools[@]} + 
        ${#crypto_tools[@]} + 
        ${#system_tools[@]}
    ))
}

# Display tool status without progress bar interference
# Draw a progress bar
progress_bar() {
{{ ... }}
    local current=$1
    local total=$2
    local size=30
    local progress=$((current * size / total))
    local remaining=$((size - progress))
    
    printf "${BLUE}["
    [ $progress -gt 0 ] && printf "${GREEN}%0.s#" $(seq 1 $progress)
    [ $remaining -gt 0 ] && printf "${DIM}%0.s·${NC}" $(seq 1 $remaining)
    printf "${BLUE}] ${WHITE}%3s%%${NC} " "$((current * 100 / total))"
}

# Cyberpunk Enhanced Tool Status Display with Holographic Effects
display_tool_status() {
    local tool=$1
    local status=$2
    local category=$3
    local current=$4
    local total=$5
    
    # Calculate progress percentage with division by zero protection
    local percentage=0
    local filled=0
    local empty=30
    
    if [ "$total" -gt 0 ]; then
        percentage=$(( (current * 100) / total ))
        # Create futuristic progress bar
        local bar_length=30
        filled=$(( (current * bar_length) / total ))
        empty=$(( bar_length - filled ))
    fi
    
    # Status icon and holographic color effects
    local status_icon=""
    local status_color=""
    local glow_effect=""
    
    case $status in
        "installed")
            status_icon="${SUCCESS_ICON}"
            status_color="${NEON_GREEN}"
            glow_effect="${BG_NEON_GREEN}${WHITE}"
            ;;
        "missing")
            status_icon="${ERROR_ICON}"
            status_color="${NEON_PINK}"
            glow_effect="${BG_RED}${WHITE}"
            ;;
    esac
    
    # Animated scanning effect
    printf "\r${ELECTRIC_BLUE}  ◈${NC} ${status_icon} "
    
    # Tool name with cyberpunk styling
    printf "${CYBER_CYAN}%-25s${NC} " "$tool"
    
    # Status with holographic effect
    printf "${glow_effect} %-10s ${NC} " "${status^^}"
    
    # Category with neon styling
    printf "${PLASMA_PURPLE}[${category}]${NC} "
    
    # Futuristic progress bar with gradient effect
    printf "${NEON_BLUE}["
    
    # Filled portion with gradient
    for ((i=0; i<filled; i++)); do
        if [ $((i % 3)) -eq 0 ]; then
            printf "${GRAD_GREEN1}${PROGRESS_FULL}"
        elif [ $((i % 3)) -eq 1 ]; then
            printf "${GRAD_GREEN2}${PROGRESS_FULL}"
        else
            printf "${GRAD_GREEN3}${PROGRESS_FULL}"
        fi
    done
    
    # Empty portion with dim effect
    printf "${DIM}${CYBER_CYAN}"
    for ((i=0; i<empty; i++)); do
        printf "${PROGRESS_EMPTY}"
    done
    
    printf "${NC}${NEON_BLUE}]${NC} "
    
    # Progress indicator with neon glow
    printf "${NEON_YELLOW}${BOLD}${current}/${total}${NC} "
    printf "${NEON_ORANGE}(${percentage}%%)${NC}"
    
    # Pulse effect for completion
    if [ "$status" = "installed" ]; then
        printf " ${NEON_GREEN}${BOLD}◉${NC}"
    elif [ "$status" = "missing" ]; then
        printf " ${NEON_PINK}${BOLD}◎${NC}"
    fi
    
    # Add newline for completed status
    if [ "$status" = "installed" ] || [ "$status" = "missing" ]; then
        echo
    fi
}

# Draw a horizontal rule with custom character
hr() {
    local width=${1:-50}
    local char=${2:-─}
    printf '%*s\n' "${width}" '' | tr ' ' "${char}"
}

# Display summary with enhanced visualization
show_summary() {
    # Calculate percentage with division by zero protection
    local percentage=0
    if [ "$TOTAL_COUNT" -gt 0 ]; then
        percentage=$(( (INSTALLED_COUNT * 100) / TOTAL_COUNT ))
    fi
    
    # Clear any progress bar
    printf "\r\033[K\n"
    
    # Summary header
    echo -e "\n${BLUE}${BOLD}📊 INSTALLATION SUMMARY${NC}"
    echo -e "${DIM}$(hr 80 "─")${NC}\n"
    
    # Category breakdown
    echo -e "  ${BOLD}📋 Category Breakdown:${NC}"
    
    # Define category mappings and totals
    declare -A category_totals
    declare -A category_installed
    declare -A category_missing
    
    # Initialize category counts
    category_totals["Network Reconnaissance"]=19
    category_totals["Web Application Security"]=23
    category_totals["Password & Authentication"]=18
    category_totals["Binary Analysis & Reverse Engineering"]=28
    category_totals["Forensics & Analysis"]=17
    category_totals["Wireless & Network Security"]=15
    category_totals["Mobile & Hardware Security"]=13
    category_totals["Exploitation Tools"]=15
    category_totals["Information Gathering (OSINT)"]=16
    category_totals["Post-Exploitation"]=8
    category_totals["Cloud Security"]=25
    category_totals["System Utilities"]=12
    category_totals["Cryptography & Hash Analysis"]=8
    
    # Count missing tools by category
    for category in "${!category_totals[@]}"; do
        category_missing["$category"]=0
    done
    
    # Count missing tools for each category
    for tool in "${MISSING_TOOLS[@]}"; do
        # Determine category based on tool name (simplified approach)
        case "$tool" in
            nmap|masscan|amass|subfinder|nuclei|rustscan|naabu|httpx|assetfinder|sublist3r|knockpy|gobuster|ffuf|dirb|dirbuster|wfuzz|feroxbuster|dirsearch|whatweb)
                ((category_missing["Network Reconnaissance"]++)) ;;
            sqlmap|wpscan|zaproxy|arjun|nikto|uniscan|skipfish|w3af|burpsuite|commix|xsser|sqlninja|jsql-injection|wapiti|cadaver|davtest|padbuster|joomscan|droopescan|cmsmap|nosqlmap|tplmap|graphql-voyager)
                ((category_missing["Web Application Security"]++)) ;;
            hydra|john|hashcat|medusa|patator|crackmapexec|ncrack|crowbar|brutespray|thc-hydra|ophcrack|rainbowcrack|hashcat-utils|pack|kwprocessor|hash-identifier|hashid|crackstation)
                ((category_missing["Password & Authentication"]++)) ;;
            gdb|radare2|binwalk|checksec|strings|objdump|xxd|hexdump|ghidra|ida-free|cutter|pwntools|ropper|one-gadget|peda|gef|pwngdb|voltron|gdb-peda|gdb-gef|binary-ninja|ropgadget|angr|libc-database|pwninit|upx|readelf|cyberchef)
                ((category_missing["Binary Analysis & Reverse Engineering"]++)) ;;
            volatility3|autopsy|bulk-extractor|scalpel|testdisk|dc3dd|ddrescue|foremost|photorec|sleuthkit|afflib-tools|libewf-tools|steghide|stegsolve|zsteg|outguess|exiftool)
                ((category_missing["Forensics & Analysis"]++)) ;;
            aircrack-ng|reaver|wifite|kismet|wireshark|tshark|tcpdump|ettercap|bettercap|hostapd|dnsmasq|macchanger|mdk3|mdk4|pixiewps)
                ((category_missing["Wireless & Network Security"]++)) ;;
            aapt|adb|fastboot|usbmuxd|libimobiledevice-utils|apktool|dex2jar|jd-gui|jadx|frida|objection|drozer|evil-winrm)
                ((category_missing["Mobile & Hardware Security"]++)) ;;
            metasploit-framework|msfvenom|msfconsole|searchsploit|exploit-db|beef-xss|armitage|cobalt-strike|empire|powersploit|mimikatz|responder|impacket|bloodhound|powerview)
                ((category_missing["Exploitation Tools"]++)) ;;
            theHarvester|recon-ng|maltego|spiderfoot|shodan|censys-python|fierce|dnsrecon|dnsenum|dmitry|sherlock|social-analyzer|pipl|trufflehog|have-i-been-pwned|subjack)
                ((category_missing["Information Gathering (OSINT)"]++)) ;;
            linpeas|winpeas|linenum|linux-exploit-suggester|windows-exploit-suggester|privesc-check|unix-privesc-check|gtfoblookup)
                ((category_missing["Post-Exploitation"]++)) ;;
            aws-cli|azure-cli|gcloud|kubectl|docker|trivy|cloudsplaining|pacu|prowler|scout-suite|cloudmapper|clair|kube-hunter|kube-bench|docker-bench-security|falco|checkov|terrascan|cloudsploit|helm|istio|opa|volatility|msfvenom-cloud|cloudgoat)
                ((category_missing["Cloud Security"]++)) ;;
            curl|wget|git|vim|nano|tmux|htop|netstat|ss|ncat|socat|netcat)
                ((category_missing["System Utilities"]++)) ;;
            cipher-identifier|frequency-analysis|rsatool|factordb|hashcat-legacy|hash-buster|findmyhash|hash-analyzer)
                ((category_missing["Cryptography & Hash Analysis"]++)) ;;
        esac
    done
    
    # Calculate installed counts and display
    for category in "${!category_totals[@]}"; do
        total=${category_totals["$category"]}
        missing=${category_missing["$category"]}
        installed=$((total - missing))
        
        if [ $total -gt 0 ]; then
            cat_percentage=$(( (installed * 100) / total ))
        else
            cat_percentage=0
        fi
        
        # Determine color based on percentage
        if [ $cat_percentage -ge 90 ]; then
            cat_color="$GREEN"
        elif [ $cat_percentage -ge 70 ]; then
            cat_color="$YELLOW"
        elif [ $cat_percentage -ge 50 ]; then
            cat_color="$ORANGE"
        else
            cat_color="$RED"
        fi
        
        # Create mini progress bar
        local bar_length=20
        local filled=$(( (cat_percentage * bar_length) / 100 ))
        local empty=$(( bar_length - filled ))
        
        printf "    ${cat_color}%-35s${NC} " "$category"
        printf "${cat_color}"
        for ((i=0; i<filled; i++)); do printf "█"; done
        printf "${DIM}"
        for ((i=0; i<empty; i++)); do printf "░"; done
        printf "${NC} ${cat_color}$installed/$total (${cat_percentage}%%)${NC}\n"
    done
    
    # Missing tools section
    if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
        echo -e "\n  ${BOLD}🔍 Missing Tools (${#MISSING_TOOLS[@]}):${NC}"
        local count=0
        for tool_info in "${MISSING_TOOLS[@]}"; do
            IFS='|' read -r tool_name category <<< "$tool_info"
            printf "  ${CROSS_MARK} %-30s ${DIM}%s${NC}\n" "$tool_name" "($category)"
            ((count++))
            [ $count -ge 10 ] && [ $count -lt ${#MISSING_TOOLS[@]} ] && {
                echo -e "  ${DIM}... and $(( ${#MISSING_TOOLS[@]} - count )) more${NC}"
                break
            }
        done
    fi
    
    # Installation hint
    if [ $MISSING_COUNT -gt 0 ]; then
        echo -e "\n  ${BOLD}${YELLOW}💡 Tip:${NC} Install missing tools with ${BOLD}${CYAN}./$(basename "$0") install${NC}"
    fi
    
    # Final message
    echo -e "\n${DIM}$(hr 80 "─")${NC}"
    echo -e "  ${BOLD}${GREEN}✅ Scan complete!${NC} ${DIM}$(date +'%Y-%m-%d %H:%M:%S')${NC}"
}

# Main tool checking function (COMPREHENSIVE VERSION)
check_all_tools() {
    calculate_total_tools
    local current=0
    
    # Clear screen and show initial progress
    clear
    echo -e "${BOLD}${CYAN}🔍 Scanning for security tools...${NC}\n"
    
    # Network Reconnaissance & Scanning (47 tools)
    show_category_header "Network Reconnaissance & Scanning" "🔍"
    local network_tools=("nmap" "amass" "subfinder" "nuclei" "masscan" "rustscan" "naabu" "httpx" "assetfinder" "sublist3r" "knockpy" "gobuster" "ffuf" "dirb" "dirbuster" "wfuzz" "feroxbuster" "dirsearch" "whatweb" "wafw00f" "eyewitness" "aquatone" "gowitness" "httprobe" "waybackurls" "autorecon" "arp-scan" "nbtscan" "rpcclient" "enum4linux" "enum4linux-ng" "smbmap" "netexec" "katana" "hakrawler" "gau" "paramspider" "x8" "jaeles" "dalfox" "testssl" "sslscan" "sslyze" "anew" "qsreplace" "uro" "jwt-tool")
    for tool in "${network_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Network"; then
            display_tool_status "$tool" "installed" "Network" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Network" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Web Application Security (23 tools)
    show_category_header "Web Application Security" "🌐"
    local web_tools=("sqlmap" "wpscan" "zaproxy" "arjun" "nikto" "uniscan" "skipfish" "w3af" "burpsuite" "commix" "xsser" "sqlninja" "jsql-injection" "wapiti" "cadaver" "davtest" "padbuster" "joomscan" "droopescan" "cmsmap" "nosqlmap" "tplmap" "graphql-voyager")
    for tool in "${web_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Web Security"; then
            display_tool_status "$tool" "installed" "Web Security" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Web Security" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Password & Authentication (18 tools)
    show_category_header "Password & Authentication" "🔐"
    local auth_tools=("hydra" "john" "hashcat" "medusa" "patator" "crackmapexec" "ncrack" "crowbar" "brutespray" "thc-hydra" "ophcrack" "rainbowcrack" "hashcat-utils" "pack" "kwprocessor" "hash-identifier" "hashid" "crackstation")
    for tool in "${auth_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Authentication"; then
            display_tool_status "$tool" "installed" "Authentication" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Authentication" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Binary Analysis & Reverse Engineering (28 tools)
    show_category_header "Binary Analysis & Reverse Engineering" "🔬"
    local binary_tools=("gdb" "radare2" "binwalk" "checksec" "strings" "objdump" "xxd" "hexdump" "ghidra" "ida-free" "cutter" "pwntools" "ropper" "one-gadget" "peda" "gef" "pwngdb" "voltron" "gdb-peda" "gdb-gef" "binary-ninja" "ropgadget" "angr" "libc-database" "pwninit" "upx" "readelf" "cyberchef")
    for tool in "${binary_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Binary Analysis"; then
            display_tool_status "$tool" "installed" "Binary Analysis" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Binary Analysis" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Forensics & Analysis (17 tools)
    show_category_header "Forensics & Analysis" "🔍"
    local forensics_tools=("volatility3" "autopsy" "bulk-extractor" "scalpel" "testdisk" "dc3dd" "ddrescue" "foremost" "photorec" "sleuthkit" "afflib-tools" "libewf-tools" "steghide" "stegsolve" "zsteg" "outguess" "exiftool")
    for tool in "${forensics_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Forensics"; then
            display_tool_status "$tool" "installed" "Forensics" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Forensics" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Wireless & Network Security (15 tools)
    show_category_header "Wireless & Network Security" "📡"
    local wireless_tools=("aircrack-ng" "reaver" "wifite" "kismet" "wireshark" "tshark" "tcpdump" "ettercap" "bettercap" "hostapd" "dnsmasq" "macchanger" "mdk3" "mdk4" "pixiewps")
    for tool in "${wireless_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Wireless Security"; then
            display_tool_status "$tool" "installed" "Wireless Security" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Wireless Security" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Mobile & Hardware Security (13 tools)
    show_category_header "Mobile & Hardware Security" "📱"
    local mobile_tools=("aapt" "adb" "fastboot" "usbmuxd" "libimobiledevice-utils" "apktool" "dex2jar" "jd-gui" "jadx" "frida" "objection" "drozer" "evil-winrm")
    for tool in "${mobile_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Mobile Security"; then
            display_tool_status "$tool" "installed" "Mobile Security" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Mobile Security" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Exploitation Tools (15 tools)
    show_category_header "Exploitation Tools" "💥"
    local exploit_tools=("metasploit-framework" "msfvenom" "msfconsole" "searchsploit" "exploit-db" "beef-xss" "armitage" "cobalt-strike" "empire" "powersploit" "mimikatz" "responder" "impacket" "bloodhound" "powerview")
    for tool in "${exploit_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Exploitation"; then
            display_tool_status "$tool" "installed" "Exploitation" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Exploitation" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Information Gathering (16 tools)
    show_category_header "Information Gathering (OSINT)" "🕵️"
    local osint_tools=("theHarvester" "recon-ng" "maltego" "spiderfoot" "shodan" "censys-python" "fierce" "dnsrecon" "dnsenum" "dmitry" "sherlock" "social-analyzer" "pipl" "trufflehog" "have-i-been-pwned" "subjack")
    for tool in "${osint_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "OSINT"; then
            display_tool_status "$tool" "installed" "OSINT" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "OSINT" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Post-Exploitation (8 tools)
    show_category_header "Post-Exploitation" "🎯"
    local post_exploit_tools=("linpeas" "winpeas" "linenum" "linux-exploit-suggester" "windows-exploit-suggester" "privesc-check" "unix-privesc-check" "gtfoblookup")
    for tool in "${post_exploit_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Post-Exploitation"; then
            display_tool_status "$tool" "installed" "Post-Exploitation" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Post-Exploitation" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Cloud Security (25 tools)
    show_category_header "Cloud Security" "☁️"
    local cloud_tools=("aws-cli" "azure-cli" "gcloud" "kubectl" "docker" "trivy" "cloudsplaining" "pacu" "prowler" "scout-suite" "cloudmapper" "clair" "kube-hunter" "kube-bench" "docker-bench-security" "falco" "checkov" "terrascan" "cloudsploit" "helm" "istio" "opa" "volatility" "msfvenom-cloud" "cloudgoat")
    for tool in "${cloud_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Cloud Security"; then
            display_tool_status "$tool" "installed" "Cloud Security" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Cloud Security" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # System Utilities (12 tools)
    show_category_header "System Utilities" "🛠️"
    local system_tools=("curl" "wget" "git" "vim" "nano" "tmux" "htop" "netstat" "ss" "ncat" "socat" "netcat")
    for tool in "${system_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "System"; then
            display_tool_status "$tool" "installed" "System" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "System" "$current" "$TOTAL_COUNT"
        fi
    done
    
    # Cryptography & Hash Analysis (8 tools)
    show_category_header "Cryptography & Hash Analysis" "🔐"
    local crypto_tools=("cipher-identifier" "frequency-analysis" "rsatool" "factordb" "hashcat-legacy" "hash-buster" "findmyhash" "hash-analyzer")
    for tool in "${crypto_tools[@]}"; do
        current=$((current + 1))
        if check_tool "$tool" "" "Cryptography"; then
            display_tool_status "$tool" "installed" "Cryptography" "$current" "$TOTAL_COUNT"
        else
            display_tool_status "$tool" "missing" "Cryptography" "$current" "$TOTAL_COUNT"
        fi
    done
    
    echo ""  # Clear progress line
}

# Display installation commands with enhanced formatting and user experience
show_installation_commands() {
    if [ $MISSING_COUNT -eq 0 ]; then
        return
    fi
    
    echo -e "\n${YELLOW}${BOLD}📦 Installation Commands for Missing Tools${NC}"
    echo -e "${YELLOW}${BOLD}======================================${NC}\n"
    
    # Group tools by package manager with better organization
    declare -A packages
    declare -A descriptions
    
    # Tool descriptions for better user understanding
    descriptions=(
        ["metasploit-framework"]="Penetration testing framework"
        ["beef-xss"]="Browser Exploitation Framework"
        ["bloodhound"]="Active Directory security analysis"
        ["theharvester"]="E-mail, subdomain, and name scraper"
        ["linpeas"]="Linux privilege escalation checker"
        ["winpeas"]="Windows privilege escalation checker"
        ["aws-cli"]="AWS Command Line Interface"
        ["docker"]="Containerization platform"
        ["kubectl"]="Kubernetes command-line tool"
        ["hashcat"]="Advanced password recovery"
    )
    
    # Categorize missing tools by package manager
    for tool in "${MISSING_TOOLS[@]}"; do
        # Extract tool name from "tool:category" format
        pkg_name="${tool%%:*}"
        
        # Special cases where package name differs from command
        case $pkg_name in
            "metasploit-framework"|"msfvenom"|"msfconsole") pkg_name="metasploit-framework" ;;
            "beef-xss") pkg_name="beef-xss" ;;
            "armitage") pkg_name="armitage" ;;
            "cobalt-strike") pkg_name="cobaltstrike" ;;
            "empire") pkg_name="powershell-empire" ;;
            "powersploit") pkg_name="powersploit" ;;
            "mimikatz") pkg_name="mimikatz" ;;
            "bloodhound") pkg_name="bloodhound" ;;
            "powerview") pkg_name="powersploit" ;;
            "theHarvester") pkg_name="theharvester" ;;
            "recon-ng") pkg_name="recon-ng" ;;
            "maltego") pkg_name="maltego" ;;
            "spiderfoot") pkg_name="spiderfoot" ;;
            "shodan") pkg_name="shodan" ;;
            "censys-python") pkg_name="censys" ;;
            "sherlock") pkg_name="sherlock" ;;
            "social-analyzer") pkg_name="social-analyzer" ;;
            "have-i-been-pwned") pkg_name="pwned" ;;
            "linpeas"|"winpeas") pkg_name="peass-ng" ;;
            "linenum") pkg_name="linux-exploit-suggester" ;;
            "aws-cli") pkg_name="awscli" ;;
            "azure-cli") pkg_name="azure-cli" ;;
            "gcloud") pkg_name="google-cloud-sdk" ;;
            "docker") pkg_name="docker.io" ;;
            "volatility") pkg_name="volatility" ;;
        esac
        
        # Add to appropriate package manager's list
        if [[ " ${APT_TOOLS[@]} " =~ " ${pkg_name} " ]]; then
            packages["apt"]+=" $pkg_name"
        elif [[ " ${SNAP_TOOLS[@]} " =~ " ${pkg_name} " ]]; then
            packages["snap"]+=" $pkg_name"
        elif [[ " ${PIP_TOOLS[@]} " =~ " ${pkg_name} " ]]; then
            packages["pip"]+=" $pkg_name"
        elif [[ " ${GEM_TOOLS[@]} " =~ " ${pkg_name} " ]]; then
            packages["gem"]+=" $pkg_name"
        elif [[ " ${GO_TOOLS[@]} " =~ " ${pkg_name} " ]]; then
            packages["go"]+=" $pkg_name"
        elif [[ " ${CUSTOM_TOOLS[@]} " =~ " ${pkg_name} " ]]; then
            packages["custom"]+=" $pkg_name"
        else
            packages["unknown"]+=" $pkg_name"
        fi
    done
    
    # Display installation commands with better formatting
    echo -e "${CYAN}${BOLD}📋 Package Manager Commands${NC}"
    echo -e "${CYAN}──────────────────────────${NC}"
    
    # APT packages
    if [ ! -z "${packages[apt]}" ]; then
        echo -e "\n${GREEN}${BOLD}🔧 APT (System Packages):${NC}"
        echo -e "Run the following command to install via APT:"
        echo -e "${BOLD}sudo apt update && sudo apt install -y${packages[apt]}${NC}"
        echo -e "  ${DIM}# Update and install system packages${NC}\n"
    fi
    
    # Snap packages
    if [ ! -z "${packages[snap]}" ]; then
        echo -e "\n${GREEN}${BOLD}📦 SNAP (Universal Packages):${NC}"
        echo -e "Run the following commands to install via Snap:"
        for pkg in $(echo ${packages[snap]} | tr ' ' '\n' | sort -u); do
            echo -e "${BOLD}sudo snap install $pkg --classic${NC}"
            if [ ! -z "${descriptions[$pkg]}" ]; then
                echo -e "  ${DIM}# ${descriptions[$pkg]}${NC}"
            fi
        done
        echo
    fi
    
    # PIP packages
    if [ ! -z "${packages[pip]}" ]; then
        echo -e "\n${GREEN}${BOLD}🐍 PIP (Python Packages):${NC}"
        echo -e "Run the following command to install via PIP:"
        echo -e "${BOLD}pip3 install --user${packages[pip]}${NC}"
        echo -e "  ${DIM}# Install Python packages for the current user${NC}\n"
    fi
    
    # GEM packages
    if [ ! -z "${packages[gem]}" ]; then
        echo -e "\n${GREEN}${BOLD}💎 GEM (Ruby Gems):${NC}"
        echo -e "Run the following command to install via GEM:"
        echo -e "${BOLD}sudo gem install${packages[gem]}${NC}\n"
    fi
    
    # GO packages
    if [ ! -z "${packages[go]}" ]; then
        echo -e "\n${GREEN}${BOLD}🐹 GO (Go Packages):${NC}"
        echo -e "Run the following commands to install Go tools:"
        for pkg in $(echo ${packages[go]} | tr ' ' '\n' | sort -u); do
            echo -e "${BOLD}go install $pkg@latest${NC}"
            if [ ! -z "${descriptions[$pkg]}" ]; then
                echo -e "  ${DIM}# ${descriptions[$pkg]}${NC}"
            fi
        done
        echo -e "${DIM}# Make sure $GOPATH/bin is in your PATH${NC}\n"
    fi
    
    # Custom installations
    if [ ! -z "${packages[custom]}" ]; then
        echo -e "\n${YELLOW}${BOLD}🔧 Custom Installations Required:${NC}"
        for pkg in $(echo ${packages[custom]} | tr ' ' '\n' | sort -u); do
            echo -e "${YELLOW}${BOLD}$pkg${NC}"
            if [ ! -z "${descriptions[$pkg]}" ]; then
                echo -e "  ${DIM}${descriptions[$pkg]}${NC}"
            fi
            echo -e "  ${DIM}Please refer to the official documentation for installation instructions.${NC}\n"
        done
    fi
    
    # Unknown packages
    if [ ! -z "${packages[unknown]}" ]; then
        echo -e "\n${RED}${BOLD}❓ Manual Installation Required:${NC}"
        echo -e "${YELLOW}The following tools require manual installation:${NC}"
        for pkg in ${packages[unknown]}; do
            echo -e "  • ${RED}$pkg${NC}"
        done
        echo -e "\n${CYAN}${BOLD}📖 Please refer to the official documentation for installation instructions.${NC}"
        echo
    fi
    
    # Final notes
    echo -e "${CYAN}${BOLD}📝 Additional Notes:${NC}"
    echo -e "${DIM}• Some tools may require additional configuration after installation.${NC}"
    echo -e "${DIM}• For tools with custom installations, please refer to their official documentation.${NC}"
    echo -e "${DIM}• Make sure to add relevant directories to your PATH if needed.${NC}\n"
    
    # Next steps
    echo -e "${GREEN}${BOLD}🚀 Next Steps:${NC}"
    echo -e "1. Install the missing tools using the commands above"
    echo -e "2. Clone the HexStrike AI repository:"
    echo -e "   ${BOLD}git clone https://github.com/0x4m4/hexstrike-ai.git && cd hexstrike-ai${NC}"
    echo -e "3. Set up a Python virtual environment:"
    echo -e "   ${BOLD}python3 -m venv hexstrike-env${NC}"
    echo -e "   ${BOLD}source hexstrike-env/bin/activate  # Linux/Mac${NC}"
    echo -e "   # hexstrike-env\Scripts\activate   # Windows"
    echo -e "4. Install Python dependencies:"
    echo -e "   ${BOLD}pip install -r requirements.txt${NC}\n"
    
    echo -e "${GREEN}✅ HexStrike AI setup complete! Run the application with:${NC}"
    echo -e "   ${BOLD}python hexstrike.py${NC}"
}
# Main function
main() {
    detect_distro
    get_package_manager
    
    # Clear screen and show banner
    
    show_banner
    
    # Check all tools and show summary
    check_all_tools
    show_summary
    
    # Show installation commands if needed
    if [ $MISSING_COUNT -gt 0 ]; then
        show_installation_commands
    fi
    
    # Final status
    echo -e "\n${GREEN}${BOLD}🎯 HEXSTRIKE AI READY STATUS${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════════════════${NC}"
    
    # Calculate percentage with division by zero protection
    local percentage=0
    if [ "$TOTAL_COUNT" -gt 0 ]; then
        percentage=$(( (INSTALLED_COUNT * 100) / TOTAL_COUNT ))
    fi
    
    # Show overall readiness
    if [ $percentage -ge 90 ]; then
        echo -e "${GREEN}✅ Excellent! Your system is ${percentage}% ready for HexStrike AI.${NC}"
    elif [ $percentage -ge 70 ]; then
        echo -e "${YELLOW}🟡 Good! Your system is ${percentage}% ready for HexStrike AI.${NC}"
    elif [ $percentage -ge 50 ]; then
        echo -e "${ORANGE}🟠 Fair. Your system is ${percentage}% ready for HexStrike AI.${NC}"
    else
        echo -e "${RED}🔴 Needs improvement. Your system is only ${percentage}% ready for HexStrike AI.${NC}"
    fi
    
    # Show tool counts
    echo -e "\n${CYAN}${BOLD}📊 Tool Status Summary:${NC}"
    echo -e "${GREEN}✓ Installed: ${INSTALLED_COUNT}${NC} tools"
    echo -e "${RED}✗ Missing:   ${MISSING_COUNT}${NC} tools"
    echo -e "${BLUE}↻ Total:     ${TOTAL_COUNT}${NC} tools checked"
    
    # Final message
    echo -e "\n${CYAN}${BOLD}✨ HexStrike AI Tools Checker completed at $(date +"%Y-%m-%d %H:%M:%S")${NC}"
}

# Run the main function
main

echo -e "\n${WHITE}${BOLD}🤖 READY TO EMPOWER YOUR AI AGENTS WITH AUTONOMOUS CYBERSECURITY CAPABILITIES!${NC}\n"
echo -e "${CYAN}Remember: With great power comes great responsibility.${NC}"
echo -e "${CYAN}Use HexStrike AI ethically and only on systems you own or have explicit permission to test.${NC}\n"

echo -e "${PURPLE}${BOLD}Happy Hacking with HexStrike AI! 🚀💀🔥${NC}\n"
