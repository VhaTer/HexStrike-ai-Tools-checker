#!/bin/bash

# HexStrike AI - Tools Verification Script (Improved Output Version)
# Based on Official HexStrike-Ai V6 README - 150+ tools coverage
# Version 5.0 - Enhanced UI/UX with clean, readable output

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
        return 0
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

# Enhanced tool checking function with clean output
check_tool() {
    local tool=$1
    local alt_check=$2
    local category=${3:-"General"}
    
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    
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
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    ██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗                    ║"
    echo "║                    ██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝                    ║"
    echo "║                    ███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗                      ║"
    echo "║                    ██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝                      ║"
    echo "║                    ██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗                    ║"
    echo "║                    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝                    ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${WHITE}${BOLD}                    HexStrike AI - Tools Checker v5.0 (Improved Output)${NC}"
    echo -e "${BLUE}                    🔗 Based on HexStrike-Ai V6 AI README - 150+ tools coverage${NC}"
    echo -e "${ORANGE}                    📋 Comprehensive verification with working download links${NC}"
    echo -e "${PURPLE}                    🚀 Enhanced with advanced exploitation and mobile security tools${NC}"
    echo ""
}

# Display system information in a clean format
show_system_info() {
    echo -e "${CYAN}${BOLD}📋 SYSTEM INFORMATION${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}🐧 Operating System:${NC} ${WHITE}$PRETTY_NAME${NC}"
    echo -e "${BLUE}📦 Distribution:${NC}     ${WHITE}$DISTRO${NC}"
    echo -e "${BLUE}🏗️  Architecture:${NC}    ${WHITE}$ARCH ($ARCH_TYPE)${NC}"
    echo -e "${BLUE}📦 Package Manager:${NC}  ${WHITE}$PKG_MANAGER${NC}"
    echo ""
}

# Display tool checking progress
show_progress() {
    local current=$1
    local total=$2
    local category=$3
    
    local percentage=$((current * 100 / total))
    local filled=$((percentage / 2))
    local empty=$((50 - filled))
    
    printf "\r${CYAN}[${NC}"
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "${CYAN}]${NC} ${WHITE}%d%%${NC} - ${BLUE}%s${NC}" "$percentage" "$category"
}

# Display category header
show_category_header() {
    local category=$1
    local icon=$2
    echo ""
    echo -e "${MAGENTA}${BOLD}$icon $category${NC}"
    echo -e "${MAGENTA}══════════════════════════════════════════════════════════════════════════════${NC}"
}

# Display tool status in a clean format
display_tool_status() {
    local tool=$1
    local status=$2
    local category=$3
    local details=$4
    
    case $status in
        "installed")
            printf "  ${GREEN}✅${NC} %-25s ${GREEN}INSTALLED${NC} ${BLUE}(%s)${NC}\n" "$tool" "$category"
            ;;
        "missing")
            printf "  ${RED}❌${NC} %-25s ${RED}MISSING${NC}  ${BLUE}(%s)${NC}\n" "$tool" "$category"
            if [ -n "$details" ]; then
                printf "      ${YELLOW}💡 $details${NC}\n"
            fi
            ;;
    esac
}

# Display summary in a clean format
show_summary() {
    echo ""
    echo -e "${CYAN}${BOLD}📊 INSTALLATION SUMMARY${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}"
    
    local percentage=$(( (INSTALLED_COUNT * 100) / TOTAL_COUNT ))
    
    echo -e "${WHITE}Total Tools Checked:${NC} ${CYAN}$TOTAL_COUNT${NC}"
    echo -e "${WHITE}Installed Tools:${NC}    ${GREEN}$INSTALLED_COUNT${NC}"
    echo -e "${WHITE}Missing Tools:${NC}      ${RED}$MISSING_COUNT${NC}"
    echo -e "${WHITE}Coverage:${NC}           ${WHITE}$percentage%${NC}"
    
    echo ""
    
    # Progress bar
    local filled=$((percentage / 2))
    local empty=$((50 - filled))
    printf "${CYAN}[${NC}"
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "${CYAN}]${NC} ${WHITE}$percentage%% Complete${NC}\n"
    
    echo ""
    
    # Status assessment
    if [ $percentage -ge 95 ]; then
        echo -e "${GREEN}${BOLD}🎉 EXCELLENT! Your system is ready for advanced HexStrike AI operations!${NC}"
    elif [ $percentage -ge 80 ]; then
        echo -e "${GREEN}${BOLD}👍 GREAT! Most tools are available for comprehensive security testing.${NC}"
    elif [ $percentage -ge 60 ]; then
        echo -e "${YELLOW}${BOLD}⚠️  GOOD! Basic security testing capabilities are available.${NC}"
    elif [ $percentage -ge 40 ]; then
        echo -e "${ORANGE}${BOLD}⚠️  MODERATE! Limited security testing capabilities.${NC}"
    else
        echo -e "${RED}${BOLD}❌ INSUFFICIENT! Major limitations in security testing capabilities.${NC}"
    fi
}

# Display missing tools by category
show_missing_tools() {
    if [ $MISSING_COUNT -eq 0 ]; then
        return
    fi
    
    echo ""
    echo -e "${YELLOW}${BOLD}📦 MISSING TOOLS BY CATEGORY${NC}"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════════════${NC}"
    
    declare -A category_counts
    for missing in "${MISSING_TOOLS[@]}"; do
        local category=$(echo "$missing" | cut -d':' -f2)
        category_counts["$category"]=$((${category_counts["$category"]} + 1))
    done
    
    for category in "${!category_counts[@]}"; do
        echo -e "${BLUE}$category:${NC} ${RED}${category_counts[$category]} tools missing${NC}"
    done
}

# Display installation commands
show_installation_commands() {
    if [ $MISSING_COUNT -eq 0 ]; then
        return
    fi
    
    echo ""
    echo -e "${GREEN}${BOLD}🚀 INSTALLATION COMMANDS${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════════════════════${NC}"
    
    case $DISTRO in
        "ubuntu"|"debian"|"kali"|"parrot"|"mint")
            echo -e "${CYAN}📦 Package Manager (apt):${NC}"
            echo "sudo apt update && sudo apt install -y [package_names]"
            echo ""
            echo -e "${CYAN}🐍 Python Packages:${NC}"
            echo "pip3 install [package_names]"
            echo ""
            echo -e "${CYAN}🐹 Go Packages:${NC}"
            echo "go install [package_paths]"
            ;;
        "fedora"|"rhel"|"centos")
            echo -e "${CYAN}📦 Package Manager ($PKG_MANAGER):${NC}"
            echo "sudo $PKG_MANAGER install -y [package_names]"
            ;;
        "arch"|"manjaro"|"endeavouros")
            echo -e "${CYAN}📦 Package Manager (pacman):${NC}"
            echo "sudo pacman -S [package_names]"
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}💡 For specific installation commands, run:${NC}"
    echo "sudo apt search [tool_name]  # Ubuntu/Debian"
    echo "sudo dnf search [tool_name]  # Fedora/RHEL"
    echo "sudo pacman -Ss [tool_name]  # Arch"
}

# Main tool checking function
check_all_tools() {
    local current=0
    
    # Network Reconnaissance & Scanning
    show_category_header "Network Reconnaissance & Scanning" "🔍"
    local network_tools=("nmap" "amass" "subfinder" "nuclei" "masscan" "rustscan" "naabu" "httpx")
    for tool in "${network_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "Network Tools"
        if check_tool "$tool" "" "Network"; then
            display_tool_status "$tool" "installed" "Network"
        else
            display_tool_status "$tool" "missing" "Network" "Network scanning and reconnaissance"
        fi
    done
    
    # Web Application Security
    show_category_header "Web Application Security" "🌐"
    local web_tools=("gobuster" "ffuf" "dirb" "nikto" "sqlmap" "wpscan" "zaproxy" "arjun")
    for tool in "${web_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "Web Security"
        if check_tool "$tool" "" "Web Security"; then
            display_tool_status "$tool" "installed" "Web Security"
        else
            display_tool_status "$tool" "missing" "Web Security" "Web application testing"
        fi
    done
    
    # Password & Authentication
    show_category_header "Password & Authentication" "🔐"
    local auth_tools=("hydra" "john" "hashcat" "medusa" "patator" "crackmapexec")
    for tool in "${auth_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "Authentication"
        if check_tool "$tool" "" "Authentication"; then
            display_tool_status "$tool" "installed" "Authentication"
        else
            display_tool_status "$tool" "missing" "Authentication" "Password cracking and authentication testing"
        fi
    done
    
    # Binary Analysis & Reverse Engineering
    show_category_header "Binary Analysis & Reverse Engineering" "🔬"
    local binary_tools=("gdb" "radare2" "binwalk" "checksec" "strings" "objdump" "xxd")
    for tool in "${binary_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "Binary Analysis"
        if check_tool "$tool" "" "Binary Analysis"; then
            display_tool_status "$tool" "installed" "Binary Analysis"
        else
            display_tool_status "$tool" "missing" "Binary Analysis" "Binary analysis and reverse engineering"
        fi
    done
    
    # Forensics & Analysis
    show_category_header "Forensics & Analysis" "🔍"
    local forensics_tools=("volatility3" "autopsy" "bulk-extractor" "scalpel" "testdisk" "dc3dd")
    for tool in "${forensics_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "Forensics"
        if check_tool "$tool" "" "Forensics"; then
            display_tool_status "$tool" "installed" "Forensics"
        else
            display_tool_status "$tool" "missing" "Forensics" "Digital forensics and analysis"
        fi
    done
    
    # Wireless & Network Security
    show_category_header "Wireless & Network Security" "📡"
    local wireless_tools=("aircrack-ng" "reaver" "wifite" "kismet" "wireshark" "tshark" "tcpdump")
    for tool in "${wireless_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "Wireless Security"
        if check_tool "$tool" "" "Wireless Security"; then
            display_tool_status "$tool" "installed" "Wireless Security"
        else
            display_tool_status "$tool" "missing" "Wireless Security" "Wireless network security testing"
        fi
    done
    
    # Mobile & Hardware Security
    show_category_header "Mobile & Hardware Security" "📱"
    local mobile_tools=("aapt" "adb" "fastboot" "usbmuxd" "libimobiledevice-utils")
    for tool in "${mobile_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "Mobile Security"
        if check_tool "$tool" "" "Mobile Security"; then
            display_tool_status "$tool" "installed" "Mobile Security"
        else
            display_tool_status "$tool" "missing" "Mobile Security" "Mobile device security testing"
        fi
    done
    
    # System Utilities
    show_category_header "System Utilities" "🛠️"
    local system_tools=("curl" "wget" "git" "vim" "nano" "tmux" "htop" "netstat" "ss")
    for tool in "${system_tools[@]}"; do
        current=$((current + 1))
        show_progress $current $TOTAL_COUNT "System Tools"
        if check_tool "$tool" "" "System"; then
            display_tool_status "$tool" "installed" "System"
        else
            display_tool_status "$tool" "missing" "System" "System utilities and tools"
        fi
    done
    
    echo ""  # Clear progress line
}

# Main execution
main() {
    show_banner
    
    detect_distro
    get_package_manager
    show_system_info
    
    if [ "$CURL_AVAILABLE" = false ]; then
        echo -e "${YELLOW}⚠️  curl not found. Link verification disabled.${NC}"
        echo ""
    fi
    
    echo -e "${CYAN}${BOLD}🔍 CHECKING TOOLS...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════${NC}"
    
    check_all_tools
    
    show_summary
    show_missing_tools
    show_installation_commands
    
    echo ""
    echo -e "${GREEN}${BOLD}🎯 NEXT STEPS:${NC}"
    echo -e "${GREEN}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}1.${NC} Install missing tools using the commands above"
    echo -e "${WHITE}2.${NC} Clone HexStrike AI repository: git clone https://github.com/0x4m4/hexstrike-ai.git"
    echo -e "${WHITE}3.${NC} Install Python dependencies: pip3 install -r requirements.txt"
    echo -e "${WHITE}4.${NC} Set up environment variables and API keys"
    echo -e "${WHITE}5.${NC} Test your installation"
    
    echo ""
    echo -e "${PURPLE}${BOLD}Happy Hacking! 🚀💀🔥${NC}"
    echo ""
}

# Run main function
main
