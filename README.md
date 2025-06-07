# RegSeek

> Advanced Windows Registry forensics reference and search engine

RegSeek is a comprehensive reference tool for Windows Registry forensics artifacts. It provides detailed information about registry locations that are valuable for digital forensics investigations, incident response, and malware analysis.

# Features

- Extensive collection of Windows Registry forensics artifacts
- Multi-criteria search with filters for category, criticality, investigation type, and more
- Filter by Windows version, registry hive, criticality level, and analysis tools
- Each artifact includes forensic value, data structure, examples, and analysis tools
- Artifacts tagged by investigation scenarios (malware analysis, data exfiltration, etc.)

# Categories

- **Execution**: Program execution tracking and artifacts
- **Network**: Network connections, shares, and communication
- **Persistence**: Autostart locations and persistence mechanisms
- **User Activity**: User behavior and document access patterns
- **System**: System configuration and installed software
- **USB/Storage**: USB device history and storage artifacts
- **Security**: Security settings and access controls
- **Browser**: Web browser artifacts and configurations
- **Malware**: Malware-specific registry artifacts
- **Communication**: Messaging and communication applications

## Advanced Search

- **Category**: Filter by artifact category
- **Criticality**: High/Medium/Low priority filtering
- **Investigation Type**: Filter by investigation scenario
- **Windows Version**: Version-specific artifacts
- **Registry Hive**: HKLM, HKCU, HKCR, etc.
- **Analysis Tools**: Artifacts with or without tools

# Quick Start

### Using the Web Interface

Visit the deployed site: [https://regseek.github.io/](https://regseek.github.io/)

### Local Development

1. **Clone the repository**

   ```bash
   git clone https://github.com/regseek/regseek.git
   cd regseek
   ```

2. **Install dependencies**

   ```bash
   pip install -r scripts/requirements.txt
   ```

3. **Validate artifacts**

   ```bash
   python scripts/validate.py
   ```

4. **Build the site**

   ```bash
   python scripts/build.py
   ```

5. **Open the site**
   ```bash
   # Open site/index.html in your browser
   open site/index.html  # macOS
   start site/index.html # Windows
   ```

# Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTE.md) for details.

# License

GPL-3.0 license - see [LICENSE](LICENSE) file for details.
