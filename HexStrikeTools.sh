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
ALL_TOOLS_STATUS=()

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

declare -A TOOL_COMMANDS
TOOL_COMMANDS=(
    ["nmap"]="sudo apt install nmap"
    ["masscan"]="sudo apt install masscan"
    ["amass"]="sudo apt install amass"
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    ["rustscan"]="cargo install rustscan"
    ["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["assetfinder"]="go install github.com/tomnomnom/assetfinder@latest"
    ["sublist3r"]="pip install sublist3r"
    ["knockpy"]="pip install knockpy"
    ["gobuster"]="sudo apt install gobuster"
    ["ffuf"]="go install github.com/ffuf/ffuf@latest"
    ["dirb"]="sudo apt install dirb"
    ["dirbuster"]="sudo apt install dirbuster"
    ["wfuzz"]="pip install wfuzz"
    ["feroxbuster"]="cargo install feroxbuster"
    ["dirsearch"]="pip install dirsearch"
    ["whatweb"]="sudo apt install whatweb"
    ["wafw00f"]="pip install wafw00f"
    ["eyewitness"]="sudo apt install eyewitness"
    ["aquatone"]="go install github.com/michenriksen/aquatone@latest"
    ["gowitness"]="go install github.com/sensepost/gowitness@latest"
    ["httprobe"]="go install github.com/tomnomnom/httprobe@latest"
    ["waybackurls"]="go install github.com/tomnomnom/waybackurls@latest"
    ["autorecon"]="pip install git+https://github.com/Tib3rius/AutoRecon.git"
    ["arp-scan"]="sudo apt install arp-scan"
    ["nbtscan"]="sudo apt install nbtscan"
    ["rpcclient"]="sudo apt install smbclient"
    ["enum4linux"]="sudo apt install enum4linux"
    ["enum4linux-ng"]="pip install enum4linux-ng"
    ["smbmap"]="pip install smbmap"
    ["netexec"]="pipx install netexec"
    ["katana"]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
    ["hakrawler"]="go install github.com/hakluke/hakrawler@latest"
    ["gau"]="go install github.com/lc/gau/v2/cmd/gau@latest"
    ["paramspider"]="pip install paramspider"
    ["x8"]="N/A"
    ["jaeles"]="go install github.com/jaeles-project/jaeles@latest"
    ["dalfox"]="go install github.com/hahwul/dalfox/v2@latest"
    ["testssl"]="sudo apt install testssl.sh"
    ["sslscan"]="sudo apt install sslscan"
    ["sslyze"]="pip install sslyze"
    ["anew"]="go install github.com/tomnomnom/anew@latest"
    ["qsreplace"]="go install github.com/tomnomnom/qsreplace@latest"
    ["uro"]="pip install uro"
    ["jwt-tool"]="pip install jwt-tool"
    ["sqlmap"]="sudo apt install sqlmap"
    ["wpscan"]="gem install wpscan"
    ["zaproxy"]="sudo apt install zaproxy"
    ["arjun"]="pip install arjun"
    ["nikto"]="sudo apt install nikto"
    ["uniscan"]="sudo apt install uniscan"
    ["skipfish"]="sudo apt install skipfish"
    ["w3af"]="pip install w3af"
    ["burpsuite"]="N/A"
    ["commix"]="pip install commix"
    ["xsser"]="sudo apt install xsser"
    ["sqlninja"]="sudo apt install sqlninja"
    ["jsql-injection"]="N/A"
    ["wapiti"]="pip install wapiti-scanner"
    ["cadaver"]="sudo apt install cadaver"
    ["davtest"]="sudo apt install davtest"
    ["padbuster"]="N/A"
    ["joomscan"]="sudo apt install joomscan"
    ["droopescan"]="pip install droopescan"
    ["cmsmap"]="pip install cmsmap"
    ["nosqlmap"]="pip install nosqlmap"
    ["tplmap"]="pip install tplmap"
    ["graphql-voyager"]="N/A"
    ["hydra"]="sudo apt install hydra"
    ["john"]="sudo apt install john"
    ["hashcat"]="sudo apt install hashcat"
    ["medusa"]="sudo apt install medusa"
    ["patator"]="pip install patator"
    ["crackmapexec"]="pipx install crackmapexec"
    ["ncrack"]="sudo apt install ncrack"
    ["crowbar"]="pip install crowbar"
    ["brutespray"]="pip install brutespray"
    ["thc-hydra"]="sudo apt install hydra-gtk"
    ["ophcrack"]="sudo apt install ophcrack"
    ["rainbowcrack"]="sudo apt install rainbowcrack"
    ["hashcat-utils"]="N/A"
    ["pack"]="N/A"
    ["kwprocessor"]="N/A"
    ["hash-identifier"]="pip install hash-identifier"
    ["hashid"]="pip install hashid"
    ["crackstation"]="N/A"
    ["gdb"]="sudo apt install gdb"
    ["radare2"]="sudo apt install radare2"
    ["binwalk"]="sudo apt install binwalk"
    ["checksec"]="pip install checksec"
    ["strings"]="sudo apt install binutils"
    ["objdump"]="sudo apt install binutils"
    ["xxd"]="sudo apt install vim"
    ["hexdump"]="sudo apt install bsdmainutils"
    ["ghidra"]="N/A"
    ["ida-free"]="N/A"
    ["cutter"]="N/A"
    ["pwntools"]="pip install pwntools"
    ["ropper"]="pip install ropper"
    ["one-gadget"]="gem install one_gadget"
    ["peda"]="N/A"
    ["gef"]="N/A"
    ["pwngdb"]="N/A"
    ["voltron"]="pip install voltron"
    ["gdb-peda"]="N/A"
    ["gdb-gef"]="N/A"
    ["binary-ninja"]="N/A"
    ["ropgadget"]="pip install ropgadget"
    ["angr"]="pip install angr"
    ["libc-database"]="N/A"
    ["pwninit"]="pip install pwninit"
    ["upx"]="sudo apt install upx-ucl"
    ["readelf"]="sudo apt install binutils"
    ["cyberchef"]="N/A"
    ["volatility3"]="pip install volatility3"
    ["autopsy"]="sudo apt install autopsy"
    ["bulk-extractor"]="sudo apt install bulk-extractor"
    ["scalpel"]="sudo apt install scalpel"
    ["testdisk"]="sudo apt install testdisk"
    ["dc3dd"]="sudo apt install dc3dd"
    ["ddrescue"]="sudo apt install gddrescue"
    ["foremost"]="sudo apt install foremost"
    ["photorec"]="sudo apt install testdisk"
    ["sleuthkit"]="sudo apt install sleuthkit"
    ["afflib-tools"]="sudo apt install afflib-tools"
    ["libewf-tools"]="sudo apt install libewf-tools"
    ["steghide"]="sudo apt install steghide"
    ["stegsolve"]="N/A"
    ["zsteg"]="gem install zsteg"
    ["outguess"]="sudo apt install outguess"
    ["exiftool"]="sudo apt install libimage-exiftool-perl"
    ["aircrack-ng"]="sudo apt install aircrack-ng"
    ["reaver"]="sudo apt install reaver"
    ["wifite"]="sudo apt install wifite"
    ["kismet"]="sudo apt install kismet"
    ["wireshark"]="sudo apt install wireshark"
    ["tshark"]="sudo apt install tshark"
    ["tcpdump"]="sudo apt install tcpdump"
    ["ettercap"]="sudo apt install ettercap-graphical"
    ["bettercap"]="go install github.com/bettercap/bettercap@latest"
    ["hostapd"]="sudo apt install hostapd"
    ["dnsmasq"]="sudo apt install dnsmasq"
    ["macchanger"]="sudo apt install macchanger"
    ["mdk3"]="sudo apt install mdk3"
    ["mdk4"]="N/A"
    ["pixiewps"]="sudo apt install pixiewps"
    ["aapt"]="sudo apt install aapt"
    ["adb"]="sudo apt install adb"
    ["fastboot"]="sudo apt install fastboot"
    ["usbmuxd"]="sudo apt install usbmuxd"
    ["libimobiledevice-utils"]="sudo apt install libimobiledevice-utils"
    ["apktool"]="sudo apt install apktool"
    ["dex2jar"]="sudo apt install dex2jar"
    ["jd-gui"]="N/A"
    ["jadx"]="sudo apt install jadx"
    ["frida"]="pip install frida-tools"
    ["objection"]="pip install objection"
    ["drozer"]="pip install drozer"
    ["evil-winrm"]="gem install evil-winrm"
    ["metasploit-framework"]="N/A"
    ["msfvenom"]="N/A"
    ["msfconsole"]="N/A"
    ["searchsploit"]="sudo apt install exploitdb"
    ["exploit-db"]="sudo apt install exploitdb"
    ["beef-xss"]="sudo apt install beef-xss"
    ["armitage"]="sudo apt install armitage"
    ["cobalt-strike"]="N/A"
    ["empire"]="pip install empire"
    ["powersploit"]="N/A"
    ["mimikatz"]="N/A"
    ["responder"]="sudo apt install responder"
    ["impacket"]="pip install impacket"
    ["bloodhound"]="pip install bloodhound"
    ["powerview"]="N/A"
    ["theharvester"]="pip install theharvester"
    ["recon-ng"]="pip install recon-ng"
    ["maltego"]="N/A"
    ["spiderfoot"]="pip install spiderfoot"
    ["shodan"]="pip install shodan"
    ["censys-python"]="pip install censys"
    ["fierce"]="pip install fierce"
    ["dnsrecon"]="pip install dnsrecon"
    ["dnsenum"]="sudo apt install dnsenum"
    ["dmitry"]="sudo apt install dmitry"
    ["sherlock"]="pip install sherlock"
    ["social-analyzer"]="pip install social-analyzer"
    ["pipl"]="N/A"
    ["trufflehog"]="pip install trufflehog"
    ["have-i-been-pwned"]="pip install haveibeenpwned"
    ["subjack"]="go install github.com/haccer/subjack@latest"
    ["linpeas"]="N/A"
    ["winpeas"]="N/A"
    ["linenum"]="N/A"
    ["linux-exploit-suggester"]="N/A"
    ["windows-exploit-suggester"]="N/A"
    ["privesc-check"]="N/A"
    ["unix-privesc-check"]="N/A"
    ["gtfoblookup"]="pip install gtfoblookup"
    ["aws-cli"]="pip install awscli"
    ["azure-cli"]="pip install azure-cli"
    ["gcloud"]="N/A"
    ["kubectl"]="N/A"
    ["docker"]="sudo apt install docker.io"
    ["trivy"]="N/A"
    ["cloudsplaining"]="pip install cloudsplaining"
    ["pacu"]="pip install pacu"
    ["prowler"]="pip install prowler"
    ["scout-suite"]="pip install scout-suite"
    ["cloudmapper"]="pip install cloudmapper"
    ["clair"]="N/A"
    ["kube-hunter"]="pip install kube-hunter"
    ["kube-bench"]="N/A"
    ["docker-bench-security"]="N/A"
    ["falco"]="N/A"
    ["checkov"]="pip install checkov"
    ["terrascan"]="N/A"
    ["cloudsploit"]="N/A"
    ["helm"]="N/A"
    ["istio"]="N/A"
    ["opa"]="N/A"
    ["volatility"]="pip install volatility"
    ["msfvenom-cloud"]="N/A"
    ["cloudgoat"]="N/A"
    ["cipher-identifier"]="N/A"
    ["frequency-analysis"]="N/A"
    ["rsatool"]="pip install rsatool"
    ["factordb"]="pip install factordb"
    ["hashcat-legacy"]="N/A"
    ["hash-buster"]="N/A"
    ["findmyhash"]="sudo apt install findmyhash"
    ["hash-analyzer"]="pip install hash-analyzer"
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
    local status="MISSING"

    if command -v "$tool" &> /dev/null; then
        status="INSTALLED"
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    elif python3 -c "import ${tool//-/_}" &> /dev/null; then
        status="INSTALLED"
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    elif gem list -i "$tool" &> /dev/null; then
        status="INSTALLED"
        INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    else
        local locations=(
            "/usr/bin/$tool" "/usr/local/bin/$tool" "/opt/$tool/bin/$tool" "/opt/$tool"
            "/snap/bin/$tool" "$HOME/go/bin/$tool" "$HOME/.cargo/bin/$tool"
            "$HOME/.local/bin/$tool" "/usr/sbin/$tool" "/sbin/$tool"
        )
        for location in "${locations[@]}"; do
            if [ -x "$location" ]; then
                status="INSTALLED"
                INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
                break
            fi
        done
    fi

    if [ "$status" == "MISSING" ]; then
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
}

# Main function
main() {
    trap 'printf "\033[?25h"' EXIT
    draw_box
    show_logo
    
    local content_y=9
    
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
    for ((i=content_y; i<BOX_HEIGHT-1; i++)); do
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

    printf "\033[$(tput lines);1H"
}

# Function to display the results in a columnar format
show_report() {
    local content_y=$1
    
    # Header
    cur_mov $content_y 3
    printf "${BOLD}${YELLOW}%-25s %-20s %-10s %-30s %-30s${NC}\n" "Category" "Tool" "Status" "Install Command" "Link"
    content_y=$((content_y + 1))

    for tool_info in "${ALL_TOOLS_STATUS[@]}"; do
        IFS=',' read -r category tool_name status <<< "$tool_info"
        
        local install_cmd=${TOOL_COMMANDS[$tool_name]:-"N/A"}
        local link=${TOOL_LINKS[$tool_name]:-"N/A"}

        local status_color="${RED}"
        if [ "$status" == "INSTALLED" ]; then
            status_color="${GREEN}"
        fi

        cur_mov $content_y 3
        printf "%-25s %-20s ${status_color}%-10s${NC} %-30s %-30s\n" "$category" "$tool_name" "$status" "$install_cmd" "$link"
        content_y=$((content_y + 1))
        
        if (( content_y >= BOX_HEIGHT - 2 )); then
            cur_mov $content_y 3
            printf "${DIM}... and many more. Please expand your terminal for a full list.${NC}"
            break
        fi
    done
}

main