# 🕵️ Advanced Directory Brute-Force Scanner

## 🚀 Project Overview

This advanced directory brute-forcing tool is a powerful, flexible Python script designed for comprehensive web directory enumeration. It supports multiple scanning tools and provides robust IP scanning capabilities for cybersecurity professionals and penetration testers.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![Tool Support](https://img.shields.io/badge/tools-ffuf%20%7C%20gobuster%20%7C%20feroxbuster-green)
![License](https://img.shields.io/badge/license-MIT-red.svg)

## ✨ Key Features

- 🌐 Multi-tool Support
  - Supports ffuf, gobuster, and feroxbuster
  - Scans both HTTP and HTTPS

- 🔍 Flexible IP Scanning
  - Single IP scanning
  - IP range support
  - CIDR notation compatibility

- 🚦 Parallel Processing
  - Concurrent scanning of multiple IP addresses
  - Configurable worker threads

- 📊 Comprehensive Reporting
  - Detailed logging
  - Interesting findings highlight
  - Customizable output

- 🛡️ Advanced Configuration
  - Command-line arguments
  - YAML configuration support
  - Extensible design

## 🔧 Prerequisites

- Python 3.7+
- One or more of:
  - ffuf
  - gobuster
  - feroxbuster
- Wordlist (default provided)

## 💾 Installation

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/directory-brute-force.git
   cd directory-brute-force
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage Examples

### Basic Scan
```bash
python directory_brute.py -i ip_list.txt
```

### Advanced Scanning
```bash
python directory_brute.py \
    -i ip_list.txt \
    -t ffuf \
    -w /path/to/custom/wordlist.txt \
    -o scan_results \
    --timeout 15 \
    --extensions php,txt,html \
    -v
```

## 📝 IP List File Format

Support for multiple input formats:
```
# Single IP
192.168.1.1

# IP Range
192.168.1.1-192.168.1.254

# CIDR Notation
192.168.1.0/24
```

## 📋 Configuration Options

### Command-Line Arguments
- `-t, --tool`: Select scanning tool (ffuf/gobuster/feroxbuster)
- `-w, --wordlist`: Custom wordlist path
- `-i, --ip-list`: IP address list file
- `-o, --output`: Output directory
- `-v, --verbose`: Enable verbose logging
- `--timeout`: Request timeout
- `--extensions`: Custom file extensions
- `--max-workers`: Concurrent scan limit

### YAML Configuration
Create a `config.yaml`:
```yaml
tool: gobuster
wordlist: /path/to/wordlist.txt
extensions: txt,php,html
max_workers: 5
timeout: 10
```

## 📂 Output Structure
```
scan_results/
├── 192.168.1.1_http.txt
├── 192.168.1.1_https.txt
└── logs/directory_brute.log
```

## 🛡️ Ethical Usage Disclaimer

🚨 **Important**: This tool is intended for ethical security testing and research purposes only. 

- Use only on networks and systems you have explicit permission to test
- Unauthorized scanning may be illegal and unethical
- Respect privacy and legal boundaries

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## 📞 Contact

Your Name - [@yourtwitterhandle](https://twitter.com/atharvvvsharma)

Project Link: [https://github.com/yourusername/directory-brute-force](https://github.com/satharv/Advanced-Directory-Brute-Force-Script)

---

**Happy Scanning! 🕵️‍♂️🔍**
