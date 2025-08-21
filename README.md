## HexStrike AI Security Tools Checker `HexStrike.Tools.sh`

### Overview

**HexStrike.Tools.sh** is a script for verifying, auditing, and validating the installation and accessibility of 150+ cybersecurity tools as listed in the HexStrike AI V6 README. It offers comprehensive coverage, ensuring your penetration testing and security analysis environment is properly equipped, and is enhanced for advanced exploitation and mobile security workflows.

## Features

- **Banner & UI:** Displays an eye-catching, colorized terminal banner for easy identification.
- **Distribution Detection:** Automatically identifies your Linux distribution (Kali, Ubuntu, RHEL, etc.) for tailored tool verification.
- **Download Link Validation:** Checks working download links for tools using `curl`.
- **Comprehensive Tool Coverage:** Supports over 150 official HexStrike AI tools (network recon, exploitation, OSINT, mobile, etc.).
- **Modular & Extensible:** Easily add new tools or verification steps.

## Requirements

- Linux OS (Kali, Ubuntu, RHEL, Parrot, etc.)
- Bash shell
- `curl` (recommended for link verification)

## Installation

Clone the repository:
```bash
git clone https://github.com/VhaTer/HexStrike-ai-Tools-checker.git
cd HexStrike-ai-Tools-checker
```

## Usage

Run the script from your terminal:
```bash
chmod +x HexStrike.Tools.sh
./HexStrike.Tools.sh
```

## Output

- summary of installed, missing, or deprecated security tools.
- Status of download links for each tool.
- Distribution and environment details.

## Customization

- Add more tools to the verification list by editing the script.
- Modify color schemes or banner text for branding.
- Integrate additional validation logic as needed.

## Troubleshooting

- If colors do not display, ensure the script uses single-backslash escape codes (`\033`) and your terminal supports ANSI colors.
- Make sure `curl` is installed for link checking (`sudo apt install curl`).

## Contributing

Pull requests, issues, and suggestions are welcome! Help expand the tool list or improve detection logic.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Author

- [VhaTer](https://github.com/VhaTer)

## References

- [HexStrike AI README](https://github.com/VhaTer/HexStrike-ai-Tools-checker)
- [Kali Linux](https://www.kali.org/)
- [curl documentation](https://curl.se/docs/manpage.html)

---
