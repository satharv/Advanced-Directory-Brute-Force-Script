#!/usr/bin/env python3

import os
import sys
import argparse
import subprocess
import logging
import yaml
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional

class DirectoryBruteForcer:
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Directory Brute Forcer
        
        :param config_path: Path to the configuration YAML file
        """
        self.config = self.load_config(config_path) if config_path else {}
        self.setup_logging()

    def load_config(self, config_path: str) -> dict:
        """
        Load configuration from a YAML file
        
        :param config_path: Path to the configuration file
        :return: Dictionary of configuration settings
        """
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.warning(f"Config file not found: {config_path}")
            return {}
        except yaml.YAMLError as e:
            logging.error(f"Error parsing config file: {e}")
            return {}

    def setup_logging(self, verbose: bool = False):
        """
        Configure logging with file and console handlers
        
        :param verbose: Enable debug level logging
        """
        log_level = logging.DEBUG if verbose else logging.INFO
        log_format = '%(asctime)s - %(levelname)s: %(message)s'
        
        # Ensure logs directory exists
        os.makedirs('logs', exist_ok=True)
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler('logs/directory_brute.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def validate_inputs(self, ip_list_file: str, wordlist: str):
        """
        Validate input files exist
        
        :param ip_list_file: Path to the file containing IP addresses
        :param wordlist: Path to the wordlist file
        """
        if not os.path.exists(ip_list_file):
            raise FileNotFoundError(f"IP list file not found: {ip_list_file}")
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"Wordlist file not found: {wordlist}")

    def create_output_directory(self, output_dir: str):
        """
        Create output directory if it doesn't exist
        
        :param output_dir: Path to the output directory
        """
        os.makedirs(output_dir, exist_ok=True)
        logging.info(f"Output directory created: {output_dir}")

    def generate_ip_list(self, ip_list_file: str) -> List[str]:
        """
        Generate a list of IP addresses, supporting single IPs, ranges, and CIDR notation
        
        :param ip_list_file: Path to the file containing IP addresses
        :return: List of processed IP addresses
        """
        ips = []
        with open(ip_list_file, 'r') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                try:
                    # Check if it's a CIDR notation
                    if '/' in line:
                        network = ipaddress.ip_network(line, strict=False)
                        ips.extend(str(ip) for ip in network.hosts())
                    # Check if it's a range
                    elif '-' in line:
                        start, end = line.split('-')
                        start_ip = ipaddress.ip_address(start.strip())
                        end_ip = ipaddress.ip_address(end.strip())
                        current = int(start_ip)
                        while current <= int(end_ip):
                            ips.append(str(ipaddress.ip_address(current)))
                            current += 1
                    # Single IP
                    else:
                        ipaddress.ip_address(line)
                        ips.append(line)
                except ValueError:
                    logging.warning(f"Invalid IP format: {line}")
        
        return ips

    def run_tool(self, ip: str, wordlist: str, output_dir: str, tool: str, 
                 timeout: int = 10, extensions: Optional[str] = None):
        """
        Run directory brute-forcing tool for a given IP
        
        :param ip: Target IP address
        :param wordlist: Path to the wordlist
        :param output_dir: Directory to save output files
        :param tool: Tool to use (ffuf, gobuster, feroxbuster)
        :param timeout: Request timeout
        :param extensions: Custom file extensions
        """
        output_file_http = os.path.join(output_dir, f"{ip}_http.txt")
        output_file_https = os.path.join(output_dir, f"{ip}_https.txt")
        
        # Default extensions if not provided
        ext = extensions or "txt,php,html,aspx,jsp"
        
        try:
            # HTTP Scan
            if tool == "ffuf":
                cmd_http = [
                    "ffuf", "-w", wordlist, "-u", f"http://{ip}/FUZZ", 
                    "-o", output_file_http, "-t", "50", 
                    "-fc", "404", "-ic", "-timeout", str(timeout)
                ]
                cmd_https = [
                    "ffuf", "-w", wordlist, "-u", f"https://{ip}/FUZZ", 
                    "-o", output_file_https, "-t", "50", 
                    "-fc", "404", "-ic", "-k", "-timeout", str(timeout)
                ]
            elif tool == "gobuster":
                cmd_http = [
                    "gobuster", "dir", "-u", f"http://{ip}", 
                    "-w", wordlist, "-o", output_file_http,
                    "-t", "50", "-x", ext, "--no-error"
                ]
                cmd_https = [
                    "gobuster", "dir", "-u", f"https://{ip}", 
                    "-w", wordlist, "-o", output_file_https,
                    "-t", "50", "-x", ext, "--no-error", "-k"
                ]
            elif tool == "feroxbuster":
                cmd_http = [
                    "feroxbuster", "-u", f"http://{ip}", 
                    "-w", wordlist, "-o", output_file_http,
                    "-t", "50", "--depth", "1"
                ]
                cmd_https = [
                    "feroxbuster", "-u", f"https://{ip}", 
                    "-w", wordlist, "-o", output_file_https,
                    "-t", "50", "--depth", "1", "-k"
                ]
            else:
                raise ValueError(f"Unsupported tool: {tool}")
            
            logging.info(f"Scanning {ip} (HTTP) with {tool}")
            subprocess.run(cmd_http, timeout=timeout, check=True)
            
            logging.info(f"Scanning {ip} (HTTPS) with {tool}")
            subprocess.run(cmd_https, timeout=timeout, check=True)
            
        except subprocess.TimeoutExpired:
            logging.error(f"Scan for {ip} timed out")
        except subprocess.CalledProcessError as e:
            logging.error(f"Scan for {ip} failed: {e}")
        except Exception as e:
            logging.error(f"Unexpected error scanning {ip}: {e}")

    def analyze_results(self, output_dir: str) -> List[Tuple[str, List[str]]]:
        """
        Analyze scan results and filter interesting files
        
        :param output_dir: Directory containing scan results
        :return: List of interesting files and their contents
        """
        interesting_files = []
        interesting_status = ['200', '403', '401', '302']
        
        for file in os.listdir(output_dir):
            if file.endswith('.txt'):
                file_path = os.path.join(output_dir, file)
                try:
                    with open(file_path, 'r') as f:
                        results = f.readlines()
                        # Filter for interesting status codes
                        interesting = [
                            line.strip() for line in results 
                            if any(status in line for status in interesting_status)
                        ]
                        if interesting:
                            interesting_files.append((file, interesting))
                except Exception as e:
                    logging.error(f"Error reading {file}: {e}")
        
        return interesting_files

    def parallel_scan(self, ip_list: List[str], wordlist: str, output_dir: str, 
                     tool: str, max_workers: int = 5, **kwargs):
        """
        Perform parallel scanning of multiple IPs
        
        :param ip_list: List of IP addresses to scan
        :param wordlist: Path to the wordlist
        :param output_dir: Directory to save output files
        :param tool: Tool to use
        :param max_workers: Maximum number of concurrent scans
        :param kwargs: Additional arguments to pass to run_tool
        """
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self.run_tool, ip, wordlist, output_dir, tool, **kwargs)
                for ip in ip_list
            ]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Parallel scan failed: {e}")

    def main(self):
        """
        Main method to parse arguments and execute directory brute-forcing
        """
        parser = argparse.ArgumentParser(description="Advanced Directory Brute-Force Script")
        
        # Tool selection
        parser.add_argument("-t", "--tool", 
                            choices=["ffuf", "gobuster", "feroxbuster"], 
                            default="gobuster",
                            help="Tool to use for directory brute-forcing")
        
        # Input files
        parser.add_argument("-w", "--wordlist", 
                            default="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                            help="Path to the wordlist")
        parser.add_argument("-i", "--ip-list", required=True,
                            help="File containing IP addresses")
        
        # Output and configuration
        parser.add_argument("-o", "--output", 
                            default="directory_bruteforce",
                            help="Directory to save output files")
        parser.add_argument("-v", "--verbose", 
                            action="store_true",
                            help="Enable verbose logging")
        
        # Additional options
        parser.add_argument("--timeout", 
                            type=int, 
                            default=10,
                            help="Timeout for each request")
        parser.add_argument("--extensions", 
                            help="Custom file extensions to scan (comma-separated)")
        parser.add_argument("--config", 
                            help="Path to configuration YAML file")
        parser.add_argument("--max-workers", 
                            type=int, 
                            default=5,
                            help="Maximum number of concurrent scans")
        
        # Parse arguments
        args = parser.parse_args()
        
        # Setup logging based on verbosity
        self.setup_logging(args.verbose)
        
        try:
            # Validate inputs
            self.validate_inputs(args.ip_list, args.wordlist)
            
            # Create output directory
            self.create_output_directory(args.output)
            
            # Generate IP list (supporting various IP formats)
            ip_list = self.generate_ip_list(args.ip_list)
            logging.info(f"Scanning {len(ip_list)} IP addresses")
            
            # Perform parallel scanning
            self.parallel_scan(
                ip_list, 
                args.wordlist, 
                args.output, 
                args.tool,
                max_workers=args.max_workers,
                timeout=args.timeout,
                extensions=args.extensions
            )
            
            # Analyze results
            interesting_results = self.analyze_results(args.output)
            
            # Report interesting findings
            if interesting_results:
                print("\n--- Interesting Findings ---")
                for file, results in interesting_results:
                    print(f"\nFile: {file}")
                    for result in results:
                        print(result)
            else:
                print("No interesting files found.")
        
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            sys.exit(1)

def main():
    bruteforcer = DirectoryBruteForcer()
    bruteforcer.main()

if __name__ == "__main__":
    main()

# Sample configuration file (config.yaml)
"""
# Optional configuration file for advanced settings
tool: gobuster
wordlist: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
extensions: txt,php,html,aspx
max_workers: 5
timeout: 10
"""
