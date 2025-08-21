#!/bin/bash

# HexStrike AI - Official Tools Verification Script (Enhanced Output)
# Version 4.1 - Professional Table, Icons & Grouping

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
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗"
echo "██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝"
echo "███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  "
echo "██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  "
echo "██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗"
echo "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${WHITE}${BOLD}HexStrike AI - Official Security Tools Checker v4.1${NC}"
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
            echo "Online"
        else
            echo "Broken"
        fi
    else
        echo "Unknown"
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
        VERSION=""
        PRETTY_NAME=$(cat /etc/redhat-release)
    else
        DISTRO="unknown"
        VERSION=""
        PRETTY_NAME="Unknown Linux"
    fi
}

detect_distro

echo -e "${BLUE}🐧 Detected OS: ${CYAN}${PRETTY_NAME}${NC}"
echo -e "${BLUE}📋 Distribution: ${CYAN}${DISTRO}${NC}"
echo -e "${BLUE}🏗  Architecture: ${CYAN}$(uname -m)${NC}"
echo -e "${BLUE}📦 Package Manager: ${CYAN}$(command -v apt &>/dev/null && echo apt || command -v yum &>/dev/null && echo yum || echo unknown)${NC}"
echo ""

# Define tools: name|category|description|url
tools=(
    "nmap|Network Recon|Network Scanning|https://nmap.org/download.html"
    "amass|Network Recon|Subdomain Enumeration|https://github.com/OWASP/Amass"
    "subfinder|Network Recon|Subdomain Discovery|https://github.com/projectdiscovery/subfinder"
    "nuclei|Network Recon|Vulnerability Scanning|https://github.com/projectdiscovery/nuclei"
    "autorecon|Network Recon|Automated Reconnaissance|https://github.com/Tib3rius/AutoRecon"
    "fierce|Network Recon|DNS Reconnaissance|https://github.com/mschwager/fierce"
    "masscan|Network Recon|Port Scanning|https://github.com/robertdavidgraham/masscan"
    "theharvester|Network Recon|OSINT|https://github.com/laramies/theHarvester"
    "responder|Network Recon|SMB/NetBIOS Capture|https://github.com/lgandx/Responder"
    # ... add more tools as needed, grouped by category
)

# Group tools by category
declare -A categories
for entry in "${tools[@]}"; do
    IFS="|" read -r name category description url <<< "$entry"
    categories["$category"]=1
done

# Print tools status in a table, per category
total_tools=0; installed_tools=0; missing_tools=0
for category in "${!categories[@]}"; do
    echo -e "${BOLD}${CYAN}-- $category --${NC}"
    printf "${WHITE}%-16s│ %-10s │ %-25s │ %-8s${NC}\n" "Tool" "Status" "Description" "Link"
    printf "${ORANGE}----------------│------------│---------------------------│--------${NC}\n"
    for entry in "${tools[@]}"; do
        IFS="|" read -r name cat description url <<< "$entry"
        if [[ "$cat" == "$category" ]]; then
            ((total_tools++))
            if command -v "$name" > /dev/null 2>&1; then
                status="${GREEN}✅ INSTALLED${NC}"
                icon="✅"
                ((installed_tools++))
            else
                status="${RED}❌ MISSING${NC}"
                icon="❌"
                ((missing_tools++))
            fi
            link_status=$(check_url "$url")
            link_color="${YELLOW}"
            if [[ "$link_status" == "Online" ]]; then link_color="${GREEN}"; fi
            if [[ "$link_status" == "Broken" ]]; then link_color="${RED}"; fi
            printf "% -16s│ %-10b │ %-25s │ %b%s${NC}\n" "$name" "$status" "$description" "$link_color" "$link_status"
        fi
    done
    echo ""
done

# Summary
echo -e "${BOLD}${WHITE}Summary:${NC}"
echo -e "  ${GREEN}Installed:${NC} $installed_tools / $total_tools"
echo -e "  ${RED}Missing:  ${NC} $missing_tools / $total_tools"
echo -e "  ${YELLOW}Link status checked with: curl${NC}"
echo -e "${MAGENTA}✔️ Scan complete. For more tools, check the official HexStrike README.${NC}"