#!/bin/bash

# HexStrike AI - Tools Verification Script (V6 Complete Edition)
# Based on Official HexStrike-Ai V6 README - 200+ tools coverage
# Version 6.2 - UI Refactor

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

# Text Styles & Effects
BOLD='\033[1m'
DIM='\033[2m'
UNDERLINE='\033[4m'
STRIKETHROUGH='\033[9m'

# Futuristic Status Icons & Symbols
CHECK_MARK="${NEON_GREEN}◉${NC}"
CROSS_MARK="${NEON_PINK}◎${NC}"

# Initialize counters
INSTALLED_COUNT=0
MISSING_COUNT=0
TOTAL_COUNT=0

# Arrays to store tool information
MISSING_TOOLS=()
INSTALLED_TOOLS=()

# Globals for UI Box
BOX_START_X=0
BOX_START_Y=0
BOX_WIDTH=0
BOX_HEIGHT=0
CONTENT_WIDTH=0
CONTENT_HEIGHT=0

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

declare -A TOOL_LINKS
TOOL_LINKS=(
    ["nmap"]="https://nmap.org/download.html"
    ["masscan"]="https://github.com/robertdavidgraham/masscan"
    ["amass"]="https://github.com/OWASP/Amass/wiki/Installation-Guide"
    ["sqlmap"]="https://github.com/sqlmapproject/sqlmap"
    ["wpscan"]="https://wpscan.com/how-to-install-wpscan/"
    ["zaproxy"]="https://www.zaproxy.org/download/"
    ["hydra"]="https://github.com/vanhauser-thc/thc-hydra"
    ["john"]="https://www.openwall.com/john/"
    ["hashcat"]="https://hashcat.net/hashcat/"
    ["radare2"]="https://rada.re/n/radare2.html"
    ["binwalk"]="https://github.com/ReFirmLabs/binwalk"
    ["ghidra"]="https://ghidra-sre.org/"
    ["theharvester"]="https://github.com/laramies/theHarvester"
    ["recon-ng"]="https://github.com/lanmaster53/recon-ng"
    ["maltego"]="https://www.maltego.com/downloads/"
    ["arjun"]="https://github.com/s0md3v/Arjun"
    ["nikto"]="https://github.com/sullo/nikto"
    ["uniscan"]="https://github.com/poerschke/Uniscan"
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
    printf "${NEON_BLUE}╔"
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

# Enhanced tool checking function
check_tool() {
    local tool=$1
    local category=${2:-"General"}

    if command -v "$tool" &> /dev/null; then
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi

    local python_tool_name=${tool//-/_}
    if python3 -c "import $python_tool_name" &> /dev/null; then
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi

    if gem list -i "$tool" &> /dev/null; then
        INSTALLED_TOOLS+=("$tool")
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
        return 0
    fi

    local locations=(
        "/usr/bin/$tool" "/usr/local/bin/$tool" "/opt/$tool/bin/$tool" "/opt/$tool"
        "/snap/bin/$tool" "$HOME/go/bin/$tool" "$HOME/.cargo/bin/$tool"
        "$HOME/.local/bin/$tool" "/usr/sbin/$tool" "/sbin/$tool"
    )
    for location in "${locations[@]}"; do
        if [ -x "$location" ]; then
            INSTALLED_TOOLS+=("$tool")
            INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
            return 0
        fi
    done

    MISSING_TOOLS+=("$tool:$category")
    MISSING_COUNT=$((MISSING_COUNT + 1))
    return 1
}

calculate_total_tools() {
    TOTAL_COUNT=0
    for category in "${!TOOLS[@]}"; do
        for tool in ${TOOLS[$category]}; do
            TOTAL_COUNT=$((TOTAL_COUNT + 1))
        done
    done
}

# Main function
main() {
    trap 'printf "\033[?25h"' EXIT
    draw_box
    
    local content_y=1
    
    local title="🔥 HexStrike Tools Checker 🔥"
    local title_x=$(( (CONTENT_WIDTH - ${#title}) / 2 ))
    cur_mov $content_y $((title_x + 2))
    printf "${BOLD}${NEON_YELLOW}${title}${NC}"
    
    content_y=$((content_y + 2))
    
    local progress_bar_width=$((CONTENT_WIDTH - 2))
    
    calculate_total_tools
    local current=0
    
    for category in "${!TOOLS[@]}"; do
        for tool in ${TOOLS[$category]}; do
            current=$((current + 1))
            check_tool "$tool" "$category"

            local percentage=$(( (current * 100) / TOTAL_COUNT ))
            local filled_width=$(( (percentage * progress_bar_width) / 100 ))

            cur_mov $content_y 3
            printf "%*s\r" $CONTENT_WIDTH ""
            printf "${MATRIX_GREEN}Scanning: ${CYAN}%-20s ${NEON_ORANGE}[%s/%s]${NC}" "$tool" "$current" "$TOTAL_COUNT"

            cur_mov $((content_y + 1)) 3
            printf "%*s\r" $CONTENT_WIDTH ""
            printf "${NEON_BLUE}["
            for ((i=0; i<filled_width; i++)); do printf "█"; done
            printf "%*s" $((progress_bar_width - filled_width)) ""
            printf "] ${NEON_YELLOW}${percentage}%%${NC}"
        done
    done
    
    # Clear the progress bar lines
    cur_mov $content_y 3; printf "%*s" $CONTENT_WIDTH ""
    cur_mov $((content_y + 1)) 3; printf "%*s" $CONTENT_WIDTH ""

    # Draw separator
    cur_mov $content_y 2
    printf "${NEON_BLUE}"
    for ((i=0; i<CONTENT_WIDTH; i++)); do printf "─"; done
    printf "${NC}"

    content_y=$((content_y + 2))
    cur_mov $content_y 3
    printf "${BOLD}${GREEN}✅ Scan Complete!${NC}"
    
    content_y=$((content_y + 1))
    cur_mov $content_y 3
    printf "${BOLD}${CYAN}📊 Tool Status Summary:${NC}"
    
    cur_mov $((content_y + 1)) 3
    printf "Total Tools: ${TOTAL_COUNT} | Installed: ${GREEN}${INSTALLED_COUNT}${NC} | Missing: ${RED}${MISSING_COUNT}${NC}"

    content_y=$((content_y + 3))
    cur_mov $content_y 3
    printf "${BOLD}🔍 Missing Tools & Install Links:${NC}"
    
    local max_missing_tools=$((CONTENT_HEIGHT - content_y))
    local count=0
    for tool_info in "${MISSING_TOOLS[@]}"; do
        if (( count + content_y + 1 < BOX_HEIGHT - 1 )); then
             cur_mov $((content_y + count + 1)) 3
             printf "%*s\r" $CONTENT_WIDTH ""
        fi

        if [ $count -ge $max_missing_tools ]; then
            printf "${DIM}... and $(( ${#MISSING_TOOLS[@]} - count )) more${NC}"
            break
        fi
        
        local tool_name="${tool_info%%:*}"
        local link=${TOOL_LINKS[$tool_name]}
        if [ -z "$link" ]; then
            link="N/A"
        fi

        printf "${CROSS_MARK} %-30s ${NEON_PURPLE}${link}${NC}" "$tool_name"
        ((count++))
    done
    
    printf "\033[$(tput lines);1H"
}

main
