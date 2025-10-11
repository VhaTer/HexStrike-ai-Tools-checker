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

# Centralized Tool Definitions
declare -A TOOLS
TOOLS=(
    ["Network Reconnaissance"]="nmap masscan amass subfinder nuclei rustscan naabu httpx assetfinder sublist3r knockpy gobuster ffuf dirb dirbuster wfuzz feroxbuster dirsearch whatweb wafw00f eyewitness aquatone gowitness httprobe waybackurls autorecon arp-scan nbtscan rpcclient enum4linux enum4linux-ng smbmap netexec katana hakrawler gau paramspider x8 jaeles dalfox testssl sslscan sslyze anew qsreplace uro jwt-tool"
    ["Web Application Security"]="sqlmap wpscan zaproxy arjun nikto uniscan skipfish w3af burpsuite commix xsser sqlninja jsql-injection wapiti cadaver davtest padbuster joomscan droopescan cmsmap nosqlmap tplmap graphql-voyager"
    ["Password & Authentication"]="hydra john hashcat medusa patator crackmapexec ncrack crowbar brutespray thc-hydra ophcrack rainbowcrack hashcat-utils pack kwprocessor hash-identifier hashid crackstation"
    ["Binary Analysis & Reverse Engineering"]="gdb radare2 binwalk checksec strings objdump xxd hexdump ghidra ida-free cutter pwntools ropper one-gadget peda gef pwngdb voltron gdb-peda gdb-gef binary-ninja ropgadget angr libc-database pwninit upx readelf cyberchef"
    ["Forensics & Analysis"]="volatility3 autopsy bulk-extractor scalpel testdisk dc3dd ddrescue foremost photorec sleuthkit afflib-tools libewf-tools steghide stegsolve zsteg outguess exiftool"
    ["Wireless & Network Security"]="aircrack-ng reaver wifite kismet wireshark tshark tcpdump ettercap bettercap hostapd dnsmasq macchanger mdk3 mdk4 pixiewps"
    ["Mobile & Hardware Security"]="aapt adb fastboot usbmuxd libimobiledevice-utils apktool dex2jar jd-gui jadx frida objection drozer evil-winrm"
    ["Exploitation Tools"]="metasploit-framework msfvenom msfconsole searchsploit exploit-db beef-xss armitage cobalt-strike empire powersploit mimikatz responder impacket bloodhound powerview"
    ["Information Gathering (OSINT)"]="theharvester recon-ng maltego spiderfoot shodan censys-python fierce dnsrecon dnsenum dmitry sherlock social-analyzer pipl trufflehog have-i-been-pwned subjack"
    ["Post-Exploitation"]="linpeas winpeas linenum linux-exploit-suggester windows-exploit-suggester privesc-check unix-privesc-check gtfoblookup"
    ["Cloud Security"]="aws-cli azure-cli gcloud kubectl docker trivy cloudsplaining pacu prowler scout-suite cloudmapper clair kube-hunter kube-bench docker-bench-security falco checkov terrascan cloudsploit helm istio opa volatility msfvenom-cloud cloudgoat"
    ["System Utilities"]="curl wget git vim nano tmux screen htop iotop netstat ss lsof strace ltrace ncat socat"
    ["Cryptography & Hash Analysis"]="cipher-identifier frequency-analysis rsatool factordb hashcat-legacy hash-buster findmyhash hash-analyzer"
)


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
    TOTAL_COUNT=0
    for category in "${!TOOLS[@]}"; do
        local tools_in_category=(${TOOLS[$category]})
        TOTAL_COUNT=$((TOTAL_COUNT + ${#tools_in_category[@]}))
    done
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
    for category in "${!TOOLS[@]}"; do
        local tools_in_category=(${TOOLS[$category]})
        category_totals["$category"]=${#tools_in_category[@]}
        category_missing["$category"]=0
    done
    
    # Count missing tools for each category
    for tool_info in "${MISSING_TOOLS[@]}"; do
        local category="${tool_info#*:}"
        ((category_missing["$category"]++))
    done
    
    # Calculate installed counts and display
    for category in "${!TOOLS[@]}"; do
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
            local tool_name="${tool_info%%:*}"
            local category="${tool_info#*:}"
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
    
    for category in "${!TOOLS[@]}"; do
        local icon=""
        case "$category" in
            "Network Reconnaissance") icon="🔍" ;;
            "Web Application Security") icon="🌐" ;;
            "Password & Authentication") icon="🔐" ;;
            "Binary Analysis & Reverse Engineering") icon="🔬" ;;
            "Forensics & Analysis") icon="🔍" ;;
            "Wireless & Network Security") icon="📡" ;;
            "Mobile & Hardware Security") icon="📱" ;;
            "Exploitation Tools") icon="💥" ;;
            "Information Gathering (OSINT)") icon="🕵️" ;;
            "Post-Exploitation") icon="🎯" ;;
            "Cloud Security") icon="☁️" ;;
            "System Utilities") icon="🛠️" ;;
            "Cryptography & Hash Analysis") icon="🔐" ;;
        esac

        show_category_header "$category" "$icon"

        for tool in ${TOOLS[$category]}; do
            current=$((current + 1))
            if check_tool "$tool" "" "$category"; then
                display_tool_status "$tool" "installed" "$category" "$current" "$TOTAL_COUNT"
            else
                display_tool_status "$tool" "missing" "$category" "$current" "$TOTAL_COUNT"
            fi
        done
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
