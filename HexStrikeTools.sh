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

# Additional Stylish Colors
LIGHT_RED='\033[1;31m'
LIGHT_GREEN='\033[1;32m'
LIGHT_YELLOW='\033[1;33m'
LIGHT_BLUE='\033[1;34m'
LIGHT_MAGENTA='\033[1;35m'
LIGHT_CYAN='\033[1;36m'
DARK_GRAY='\033[1;30m'

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
ALL_TOOLS_STATUS=()

# Globals for UI Box
BOX_START_X=0
BOX_START_Y=0
BOX_WIDTH=0
BOX_HEIGHT=0
CONTENT_WIDTH=0
CONTENT_HEIGHT=0

# Function to fetch and parse the tool list from the README
fetch_and_parse_tools() {
    local url="https://raw.githubusercontent.com/0x4m4/hexstrike-ai/refs/heads/master/README.md"
    local readme_content=$(curl -s "$url")

    # Use awk to parse the content and populate the TOOLS array
    while IFS= read -r line; do
        if [[ "$line" =~ ^"###" ]]; then
            current_category=$(echo "$line" | sed -e 's/^### //' -e 's/ (.*//')
        elif [[ "$line" =~ ^"-" ]]; then
            tool_name=$(echo "$line" | awk -F'**' '{print $2}')
            if [ -n "$tool_name" ]; then
                TOOLS[$current_category]+="$tool_name "
            fi
        fi
    done <<< "$(echo "$readme_content" | awk '/## Security Tools Arsenal/,/---/')"
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

# Enhanced tool checking function for Kali Linux
check_tool() {
    local tool=$1
    local category=${2:-"General"}
    local status="MISSING"

    # Scanning animation
    local animation_chars="-\\|/"
    for ((i=0; i<5; i++)); do
        printf "\r${MATRIX_GREEN}Scanning: ${CYAN}%-20s ${animation_chars:$((i % ${#animation_chars})):1}" "$tool"
    done

    # Prioritize command -v, which is the most reliable check
    if command -v "$tool" &> /dev/null; then
        status="INSTALLED"
    # Check for pipx installations
    elif pipx list --short | grep -q "^$tool$"; then
        status="INSTALLED"
    # Check for go installations
    elif [ -f "$HOME/go/bin/$tool" ]; then
        status="INSTALLED"
    # Check for python packages
    elif python3 -c "import ${tool//-/_}" &> /dev/null; then
        status="INSTALLED"
    # Check for ruby gems
    elif gem list -i "$tool" &> /dev/null; then
        status="INSTALLED"
    fi

    if [ "$status" == "INSTALLED" ]; then
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    else
        MISSING_COUNT=$((MISSING_COUNT + 1))
    fi

    ALL_TOOLS_STATUS+=("$category,$tool,$status")
}

calculate_total_tools() {
    TOTAL_COUNT=0
    for category in "${!TOOLS[@]}"; do
        for tool in ${TOOLS[$category]}; do
            TOTAL_COUNT=$((TOTAL_COUNT + 1))
        done
    done
}

show_logo() {
    local logo_y=1
    local logo_x=$(( (CONTENT_WIDTH - 70) / 2 ))
    
    cur_mov $((logo_y++)) $((logo_x)); printf "${NEON_BLUE}  / / / /${NC}  ${NEON_PINK}__  __     ${NC}__                           ${NEON_BLUE}/ / / /${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${NEON_BLUE} / / / /${NC}   ${NEON_PINK}/ / / /__  ${NC}/ /___  _________ ________  ____${NEON_BLUE}/ / / /${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${NEON_BLUE}/ / / /${NC}    ${NEON_PINK}/ /_/ / _ \\${NC}/ / __ \\/ ___/ __ \`/ ___/ / / / __ \\  ${NEON_BLUE}/ / / /${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${NEON_BLUE} / / / /${NC}   ${NEON_PINK}/ __  /  __/${NC}/ / / / /__/ /_/ / /  / /_/ / / / / ${NEON_BLUE}/ / / /${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${NEON_BLUE}/ / / /${NC}    ${NEON_PINK}/_/ /_/\\___/${NC}/_/_/ /_/\\___/\\__,_/_/   \\__,_/_/ /_/  ${NEON_BLUE}/ / / /${NC}"
    cur_mov $((logo_y++)) $((logo_x)); printf "${NC}                                                        "
    
    logo_y=$((logo_y + 1))
    cur_mov $((logo_y)) 2
    printf "${NEON_BLUE}"
    for ((i=0; i<CONTENT_WIDTH; i++)); do printf "─"; done
    printf "${NC}"

    local title_y=$((logo_y + 1))
    local title="🔥 HexStrike Tools Checker 🔥"
    local title_x=$(( (CONTENT_WIDTH - ${#title}) / 2 ))
    cur_mov $title_y $((title_x + 2))
    printf "${BOLD}${NEON_YELLOW}${title}${NC}"
}

# Main function
main() {
    trap 'printf "\033[?25h"' EXIT
    fetch_and_parse_tools
    draw_box
    show_logo
    
    local content_y=11
    
    local progress_bar_width=$((CONTENT_WIDTH - 2))
    
    calculate_total_tools
    local current=0
    
    for category in "${!TOOLS[@]}"; do
        local category_progress_y=$((content_y))
        cur_mov $category_progress_y 3
        printf "%*s\r" $CONTENT_WIDTH ""
        printf "${BOLD}${CYBER_CYAN}Scanning Category: ${YELLOW}${category}${NC}"

        for tool in ${TOOLS[$category]}; do
            current=$((current + 1))
            check_tool "$tool" "$category"

            local percentage=$(( (current * 100) / TOTAL_COUNT ))
            local filled_width=$(( (percentage * progress_bar_width) / 100 ))

            local tool_progress_y=$((content_y + 1))
            cur_mov $tool_progress_y 3
            printf "%*s\r" $CONTENT_WIDTH ""
            printf "${MATRIX_GREEN}Checking: ${CYAN}%-20s ${NEON_ORANGE}[%s/%s]${NC}" "$tool" "$current" "$TOTAL_COUNT"

            local bar_y=$((content_y + 2))
            cur_mov $bar_y 3
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

    # Clear the screen for the report
    for ((i=content_y; i<BOX_HEIGHT-2; i++)); do
        cur_mov $i 3
        printf "%*s" $CONTENT_WIDTH ""
    done

    show_report "$content_y"

    local footer_y=$((BOX_HEIGHT - 2))
    cur_mov $footer_y 2
    printf "${NEON_BLUE}"
    for ((i=0; i<CONTENT_WIDTH; i++)); do printf "─"; done
    printf "${NC}"
    
    local footer_text_y=$((BOX_HEIGHT - 2))
    cur_mov $footer_text_y 3
    printf "${CYAN}Ethical Warning: Use these tools responsibly and only on systems you are authorized to test.${NC}\n"
    
    cur_mov $((footer_text_y + 1)) 3
    printf "${DIM}Disclaimer: Tool status may not be 100%% accurate. Please verify manually. Created By 'PureHate'${NC}"

    while true; do
        read -n 1 -s -r -t 1 key
        if [[ $key == "q" ]]; then
            break
        fi
    done
    printf "\033[?25h"
}

# Function to display the results in a columnar format
show_report() {
    local content_y=$1
    
    # Header
    cur_mov $content_y 3
    printf "${BOLD}${LIGHT_BLUE}%-22s %-18s %-10s %-30s %s${NC}\n" "Category" "Tool" "Status" "Install Command" "Link"
    cur_mov $((content_y + 1)) 2
    printf "${NEON_BLUE}"
    for ((i=0; i<CONTENT_WIDTH; i++)); do printf "─"; done
    printf "${NC}"
    content_y=$((content_y + 2))

    for tool_info in "${ALL_TOOLS_STATUS[@]}"; do
        IFS=',' read -r category tool_name status <<< "$tool_info"
        
        local install_cmd=${TOOL_COMMANDS[$tool_name]:-"N/A"}
        local link=${TOOL_LINKS[$tool_name]:-"N/A"}

        local status_color="${RED}"
        if [ "$status" == "INSTALLED" ]; then
            status_color="${GREEN}"
        fi

        cur_mov $content_y 3
        printf "%-22s %-18s ${status_color}%-10s${NC} %-30s %s\n" "$category" "$tool_name" "$status" "$install_cmd" "$link"
        content_y=$((content_y + 1))
        
        if (( content_y >= BOX_HEIGHT - 2 )); then
            cur_mov $content_y 3
            printf "${DIM}... and many more. Please expand your terminal for a full list.${NC}"
            break
        fi
    done
}

main