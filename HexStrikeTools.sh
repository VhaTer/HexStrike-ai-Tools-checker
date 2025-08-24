#!/bin/bash

# HexStrike AI - Tools Verification Script (V6 Complete Edition)
# Based on Official HexStrike-Ai V6 README - 200+ tools coverage
# Version 6.0 - Complete V6 alignment with all missing tools added

# Color definitions
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
NC='\033[0m'

# Initialize counters
INSTALLED_COUNT=0
MISSING_COUNT=0
TOTAL_COUNT=0

# Arrays to store results
INSTALLED_TOOLS=()
MISSING_TOOLS=()

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

# Clean banner display
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗  ║"
    echo "║██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝  ║"
    echo "║███████║█████╗   ╚███╔╝ ███████╗   ██║   ███████╔╝██║█████╔╝ █████╗   ║"
    echo "║██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝    ║"
    echo "║██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗  ║"
    echo "║╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝  ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${WHITE}${BOLD}                    HexStrike AI - Tools Checker v6.0 (V6 Complete)${NC}"
    echo -e "${BLUE}                    🔗 Comprehensive security tools verification - 200+ tools${NC}"
    echo -e "${ORANGE}                    📋 Advanced penetration testing toolkit checker${NC}"
    echo -e "${PURPLE}                    🚀 AI-powered security testing capabilities${NC}"
    echo ""
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
    local system_tools=("curl" "wget" "git" "vim" "nano" "tmux" "htop" "netstat" "ss" "ncat" "socat" "netcat")
    
    TOTAL_COUNT=$((${#network_tools[@]} + ${#web_tools[@]} + ${#auth_tools[@]} + ${#binary_tools[@]} + ${#forensics_tools[@]} + ${#wireless_tools[@]} + ${#mobile_tools[@]} + ${#exploit_tools[@]} + ${#osint_tools[@]} + ${#post_exploit_tools[@]} + ${#cloud_tools[@]} + ${#crypto_tools[@]} + ${#system_tools[@]}))
}

# Display category header
show_category_header() {
    local category=$1
    local icon=$2
    echo ""
    echo -e "${MAGENTA}${BOLD}$icon $category${NC}"
    echo -e "${MAGENTA}════════════════════════════════════════════════════════════════════════════${NC}"
}

# Display tool status without progress bar interference
display_tool_status() {
    local tool=$1
    local status=$2
    local category=$3
    
    case $status in
        "installed")
            printf "  ${GREEN}✅${NC} %-25s ${GREEN}INSTALLED${NC} ${BLUE}(%s)${NC}\n" "$tool" "$category"
            ;;
        "missing")
            printf "  ${RED}❌${NC} %-25s ${RED}MISSING${NC}   ${BLUE}(%s)${NC}\n" "$tool" "$category"
            ;;
    esac
}

# Display summary
show_summary() {
    echo ""
    echo -e "${CYAN}${BOLD}📊 INSTALLATION SUMMARY${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════${NC}"
    
    local percentage=$(( (INSTALLED_COUNT * 100) / TOTAL_COUNT ))
    
    echo -e "${WHITE}Total Tools Checked:${NC} ${CYAN}$TOTAL_COUNT${NC}"
    echo -e "${WHITE}Installed Tools:${NC}    ${GREEN}$INSTALLED_COUNT${NC}"
    echo -e "${WHITE}Missing Tools:${NC}      ${RED}$MISSING_COUNT${NC}"
    echo -e "${WHITE}Coverage:${NC}           ${WHITE}$percentage%${NC}"
    
    echo ""
    
    # Clean progress bar
    local filled=$((percentage / 2))
    local empty=$((50 - filled))
    printf "${CYAN}Progress: [${NC}"
    for ((i=0; i<filled; i++)); do printf "${GREEN}█${NC}"; done
    for ((i=0; i<empty; i++)); do printf "${WHITE}░${NC}"; done
    printf "${CYAN}] ${WHITE}$percentage%%${NC}\n"
    
    echo ""
    
    # Status assessment
    if [ $percentage -ge 90 ]; then
        echo -e "${GREEN}${BOLD}🎉 EXCELLENT! Your system is ready for advanced HexStrike AI operations!${NC}"
    elif [ $percentage -ge 70 ]; then
        echo -e "${GREEN}${BOLD}👍 GREAT! Most tools are available for comprehensive security testing.${NC}"
    elif [ $percentage -ge 50 ]; then
        echo -e "${YELLOW}${BOLD}⚠️  GOOD! Basic security testing capabilities are available.${NC}"
    elif [ $percentage -ge 30 ]; then
        echo -e "${ORANGE}${BOLD}⚠️  MODERATE! Limited security testing capabilities.${NC}"
    else
        echo -e "${RED}${BOLD}❌ INSUFFICIENT! Major limitations in security testing capabilities.${NC}"
    fi
}

# Main tool checking function (COMPREHENSIVE VERSION)
check_all_tools() {
    calculate_total_tools
    local current=0
    
    # Network Reconnaissance & Scanning (47 tools)
    show_category_header "Network Reconnaissance & Scanning" "🔍"
    local network_tools=("nmap" "amass" "subfinder" "nuclei" "masscan" "rustscan" "naabu" "httpx" "assetfinder" "sublist3r" "knockpy" "gobuster" "ffuf" "dirb" "dirbuster" "wfuzz" "feroxbuster" "dirsearch" "whatweb" "wafw00f" "eyewitness" "aquatone" "gowitness" "httprobe" "waybackurls" "autorecon" "arp-scan" "nbtscan" "rpcclient" "enum4linux" "enum4linux-ng" "smbmap" "netexec" "katana" "hakrawler" "gau" "paramspider" "x8" "jaeles" "dalfox" "testssl" "sslscan" "sslyze" "anew" "qsreplace" "uro" "jwt-tool")
    for tool in "${network_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Network"; then
            display_tool_status "$tool" "installed" "Network"
        else
            display_tool_status "$tool" "missing" "Network"
        fi
    done
    
    # Web Application Security (23 tools)
    show_category_header "Web Application Security" "🌐"
    local web_tools=("sqlmap" "wpscan" "zaproxy" "arjun" "nikto" "uniscan" "skipfish" "w3af" "burpsuite" "commix" "xsser" "sqlninja" "jsql-injection" "wapiti" "cadaver" "davtest" "padbuster" "joomscan" "droopescan" "cmsmap" "nosqlmap" "tplmap" "graphql-voyager")
    for tool in "${web_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Web Security"; then
            display_tool_status "$tool" "installed" "Web Security"
        else
            display_tool_status "$tool" "missing" "Web Security"
        fi
    done
    
    # Password & Authentication (18 tools)
    show_category_header "Password & Authentication" "🔐"
    local auth_tools=("hydra" "john" "hashcat" "medusa" "patator" "crackmapexec" "ncrack" "crowbar" "brutespray" "thc-hydra" "ophcrack" "rainbowcrack" "hashcat-utils" "pack" "kwprocessor" "hash-identifier" "hashid" "crackstation")
    for tool in "${auth_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Authentication"; then
            display_tool_status "$tool" "installed" "Authentication"
        else
            display_tool_status "$tool" "missing" "Authentication"
        fi
    done
    
    # Binary Analysis & Reverse Engineering (28 tools)
    show_category_header "Binary Analysis & Reverse Engineering" "🔬"
    local binary_tools=("gdb" "radare2" "binwalk" "checksec" "strings" "objdump" "xxd" "hexdump" "ghidra" "ida-free" "cutter" "pwntools" "ropper" "one-gadget" "peda" "gef" "pwngdb" "voltron" "gdb-peda" "gdb-gef" "binary-ninja" "ropgadget" "angr" "libc-database" "pwninit" "upx" "readelf" "cyberchef")
    for tool in "${binary_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Binary Analysis"; then
            display_tool_status "$tool" "installed" "Binary Analysis"
        else
            display_tool_status "$tool" "missing" "Binary Analysis"
        fi
    done
    
    # Forensics & Analysis (17 tools)
    show_category_header "Forensics & Analysis" "🔍"
    local forensics_tools=("volatility3" "autopsy" "bulk-extractor" "scalpel" "testdisk" "dc3dd" "ddrescue" "foremost" "photorec" "sleuthkit" "afflib-tools" "libewf-tools" "steghide" "stegsolve" "zsteg" "outguess" "exiftool")
    for tool in "${forensics_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Forensics"; then
            display_tool_status "$tool" "installed" "Forensics"
        else
            display_tool_status "$tool" "missing" "Forensics"
        fi
    done
    
    # Wireless & Network Security (15 tools)
    show_category_header "Wireless & Network Security" "📡"
    local wireless_tools=("aircrack-ng" "reaver" "wifite" "kismet" "wireshark" "tshark" "tcpdump" "ettercap" "bettercap" "hostapd" "dnsmasq" "macchanger" "mdk3" "mdk4" "pixiewps")
    for tool in "${wireless_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Wireless Security"; then
            display_tool_status "$tool" "installed" "Wireless Security"
        else
            display_tool_status "$tool" "missing" "Wireless Security"
        fi
    done
    
    # Mobile & Hardware Security (13 tools)
    show_category_header "Mobile & Hardware Security" "📱"
    local mobile_tools=("aapt" "adb" "fastboot" "usbmuxd" "libimobiledevice-utils" "apktool" "dex2jar" "jd-gui" "jadx" "frida" "objection" "drozer" "evil-winrm")
    for tool in "${mobile_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Mobile Security"; then
            display_tool_status "$tool" "installed" "Mobile Security"
        else
            display_tool_status "$tool" "missing" "Mobile Security"
        fi
    done
    
    # Exploitation Tools (15 tools)
    show_category_header "Exploitation Tools" "💥"
    local exploit_tools=("metasploit-framework" "msfvenom" "msfconsole" "searchsploit" "exploit-db" "beef-xss" "armitage" "cobalt-strike" "empire" "powersploit" "mimikatz" "responder" "impacket" "bloodhound" "powerview")
    for tool in "${exploit_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Exploitation"; then
            display_tool_status "$tool" "installed" "Exploitation"
        else
            display_tool_status "$tool" "missing" "Exploitation"
        fi
    done
    
    # Information Gathering (16 tools)
    show_category_header "Information Gathering (OSINT)" "🕵️"
    local osint_tools=("theHarvester" "recon-ng" "maltego" "spiderfoot" "shodan" "censys-python" "fierce" "dnsrecon" "dnsenum" "dmitry" "sherlock" "social-analyzer" "pipl" "trufflehog" "have-i-been-pwned" "subjack")
    for tool in "${osint_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "OSINT"; then
            display_tool_status "$tool" "installed" "OSINT"
        else
            display_tool_status "$tool" "missing" "OSINT"
        fi
    done
    
    # Post-Exploitation (8 tools)
    show_category_header "Post-Exploitation" "🎯"
    local post_exploit_tools=("linpeas" "winpeas" "linenum" "linux-exploit-suggester" "windows-exploit-suggester" "privesc-check" "unix-privesc-check" "gtfoblookup")
    for tool in "${post_exploit_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Post-Exploitation"; then
            display_tool_status "$tool" "installed" "Post-Exploitation"
        else
            display_tool_status "$tool" "missing" "Post-Exploitation"
        fi
    done
    
    # Cloud Security (25 tools)
    show_category_header "Cloud Security" "☁️"
    local cloud_tools=("aws-cli" "azure-cli" "gcloud" "kubectl" "docker" "trivy" "cloudsplaining" "pacu" "prowler" "scout-suite" "cloudmapper" "clair" "kube-hunter" "kube-bench" "docker-bench-security" "falco" "checkov" "terrascan" "cloudsploit" "helm" "istio" "opa" "volatility" "msfvenom-cloud" "cloudgoat")
    for tool in "${cloud_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Cloud Security"; then
            display_tool_status "$tool" "installed" "Cloud Security"
        else
            display_tool_status "$tool" "missing" "Cloud Security"
        fi
    done
    
    # System Utilities (12 tools)
    show_category_header "System Utilities" "🛠️"
    local system_tools=("curl" "wget" "git" "vim" "nano" "tmux" "htop" "netstat" "ss" "ncat" "socat" "netcat")
    for tool in "${system_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "System"; then
            display_tool_status "$tool" "installed" "System"
        else
            display_tool_status "$tool" "missing" "System"
        fi
    done
    
    # Cryptography & Hash Analysis (8 tools)
    show_category_header "Cryptography & Hash Analysis" "🔐"
    local crypto_tools=("cipher-identifier" "frequency-analysis" "rsatool" "factordb" "hashcat-legacy" "hash-buster" "findmyhash" "hash-analyzer")
    for tool in "${crypto_tools[@]}"; do
        current=$((current + 1))
        printf "\r${CYAN}Checking tools... ${WHITE}$current/$TOTAL_COUNT${NC} (${CYAN}$(($current * 100 / $TOTAL_COUNT))%%${NC})"
        if check_tool "$tool" "" "Cryptography"; then
            display_tool_status "$tool" "installed" "Cryptography"
        else
            display_tool_status "$tool" "missing" "Cryptography"
        fi
    done
    
    echo ""  # Clear progress line
}

# Display installation commands
show_installation_commands() {
    if [ $MISSING_COUNT -eq 0 ]; then
        return
    fi
    
    echo ""
    echo -e "${GREEN}${BOLD}🚀 QUICK INSTALLATION GUIDE${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════════════════${NC}"
    
    case $DISTRO in
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            echo -e "${CYAN}📦 Essential Security Tools (apt):${NC}"
            echo "sudo apt update && sudo apt install -y nmap masscan gobuster ffuf sqlmap hydra john hashcat nikto wireshark aircrack-ng metasploit-framework burpsuite zaproxy"
            echo ""
            echo -e "${CYAN}🐍 Python Security Tools:${NC}"
            echo "pip3 install subfinder nuclei amass theHarvester impacket"
            echo ""
            echo -e "${CYAN}🐹 Go Security Tools:${NC}"
            echo "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            echo "go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
            echo "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
            ;;
        "arch"|"manjaro"|"endeavouros")
            echo -e "${CYAN}📦 Essential Security Tools (pacman):${NC}"
            echo "sudo pacman -S nmap masscan gobuster sqlmap hydra john hashcat nikto wireshark-qt aircrack-ng metasploit burpsuite zaproxy"
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}💡 For complete HexStrike AI setup:${NC}"
    echo "1. Install missing tools above"
    echo "2. git clone https://github.com/0x4m4/hexstrike-ai.git && cd hexstrike-ai"
    echo "3. Create virtual environment"
    echo "   python3 -m venv hexstrike-env"
    echo "   source hexstrike-env/bin/activate  # Linux/Mac"
    echo "   # hexstrike-env\Scripts\activate   # Windows"
    echo "4. Install Python dependencies"  
    echo "   pip3 install -r requirements.txt"
}

# Main execution
main() {
    show_banner
    
    detect_distro
    get_package_manager
    show_system_info
    
    echo -e "${CYAN}${BOLD}🔍 CHECKING SECURITY TOOLS...${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════${NC}"
    
    check_all_tools
    
    show_summary
    show_installation_commands
    
    echo ""
    echo -e "${GREEN}${BOLD}🎯 HEXSTRIKE AI READY STATUS${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════════════════${NC}"
    
    local percentage=$(( (INSTALLED_COUNT * 100) / TOTAL_COUNT ))
    if [ $percentage -ge 70 ]; then
        echo -e "${GREEN}🟢 Your system is ready for HexStrike AI operations!${NC}"
    elif [ $percentage -ge 40 ]; then
        echo -e "${YELLOW}🟡 Partial readiness - install missing tools for full capabilities${NC}"
    else
        echo -e "${RED}🔴 Additional tools required for optimal HexStrike AI performance${NC}"
    fi
    echo ""
    echo -e "${WHITE}${BOLD}🤖 READY TO EMPOWER YOUR AI AGENTS WITH AUTONOMOUS CYBERSECURITY CAPABILITIES!${NC}"
    echo ""
    echo -e "${CYAN}Remember: With great power comes great responsibility.${NC}"
    echo -e "${CYAN}Use HexStrike AI ethically and only.${NC}"
    echo -e "${CYAN}on systems you own or have explicit permission to test.${NC}"
    echo ""
    echo ""
    echo ""
    echo -e "${PURPLE}${BOLD}Happy Hacking with HexStrike AI! 🚀💀🔥${NC}"
    echo ""
  
}

# Run main function
main
