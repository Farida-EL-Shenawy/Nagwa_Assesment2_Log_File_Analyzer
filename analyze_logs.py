# analyze_logs.py

import re
import random
import requests
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

# --- Configuration & Setup ---

# Pre-compile the regular expression for efficiency.
LOG_PATTERN = re.compile(
    r'^(?P<ip_address>\S+) '
    r'\S+ '
    r'\S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<http_method>[A-Z]+) '
    r'(?P<path>\S+) '
    r'\S+" '
    r'(?P<status_code>\d{3}) '
    r'.*$'
)

# --- Core Functions ---

def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    match = LOG_PATTERN.match(line)
    if match:
        data = match.groupdict()
        data['status_code'] = int(data['status_code'])
        return data
    return None

def geolocate_ip(ip_address: str) -> str:
    """
    Finds the geographical location of an IP address using the ip-api.com API.

    Args:
        ip_address: The IP address to geolocate.

    Returns:
        A formatted string "City, Country" if successful, otherwise "Location not found."
    """
    # The API will fail for private/reserved IPs, which is expected.
    # The error handling below will gracefully manage these cases.
    api_url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get('status') == 'success':
            city = data.get('city', 'N/A')
            country = data.get('country', 'N/A')
            return f"{city}, {country}"
        else:
            return "Location not found."
    except requests.exceptions.RequestException:
        return "Location not found."

def analyze_log_file(file_path: str) -> Optional[Dict[str, Any]]:
    print(f"\n🔍 Analyzing '{file_path}'...")
    stats = {
        'total_requests': 0,
        'status_code_counts': {},
        'ip_counts': {},
        'endpoint_counts': {}
    }
    try:
        with open(file_path, 'r') as f:
            for line in f:
                parsed_data = parse_log_line(line)
                if parsed_data:
                    stats['total_requests'] += 1
                    ip = parsed_data['ip_address']
                    stats['ip_counts'][ip] = stats['ip_counts'].get(ip, 0) + 1
                    code = parsed_data['status_code']
                    stats['status_code_counts'][code] = stats['status_code_counts'].get(code, 0) + 1
                    path = parsed_data['path']
                    stats['endpoint_counts'][path] = stats['endpoint_counts'].get(path, 0) + 1
        print("✅ Analysis complete.")
        return stats
    except FileNotFoundError:
        print(f"❌ Error: The file '{file_path}' was not found.")
        return None

def identify_issues(stats: Dict[str, Any]) -> List[str]:
    issues = []
    total_requests = stats.get('total_requests', 0)
    if total_requests > 0:
        error_count = sum(count for code, count in stats.get('status_code_counts', {}).items() if code >= 400)
        error_rate = (error_count / total_requests) * 100
        if error_rate > 10.0:
            issues.append(f"🚨 High Error Rate: {error_rate:.2f}% of requests failed.")
    request_threshold = 15
    print("🛡️  Checking for suspicious IP activity...")
    for ip, count in stats.get('ip_counts', {}).items():
        if count > request_threshold:
            location = geolocate_ip(ip)
            warning_msg = (
                f"Suspicious IP Activity: IP {ip} made {count} requests. "
                f"Location: {location}"
            )
            issues.append(warning_msg)
    return issues

# --- Reporting Functions ---

def print_console_report(stats: Dict[str, Any], issues: List[str]):
    """Prints a beautifully formatted analysis report to the console."""
    
    print("\n" + "="*50)
    print("--- 📊 LOG ANALYSIS REPORT ---")
    print("="*50)
    
    print(f"\nTotal Requests Processed: {stats['total_requests']}\n")
    
    print("--- Status Code Breakdown ---")
    for code, count in sorted(stats['status_code_counts'].items()):
        print(f"  - {code}: {count} responses")
        
    print("\n--- Top 5 Most Active IP Addresses ---")
    top_ips = sorted(stats['ip_counts'].items(), key=lambda item: item[1], reverse=True)[:5]
    for ip, count in top_ips:
        print(f"  - {ip}: {count} requests")
        
    print("\n--- Top 5 Most Requested Endpoints ---")
    top_endpoints = sorted(stats['endpoint_counts'].items(), key=lambda item: item[1], reverse=True)[:5]
    for path, count in top_endpoints:
        print(f"  - {path}: {count} requests")
    
    print("\n" + "="*50)
    print("--- ❗ POTENTIAL ISSUES ---")
    print("="*50)
    
    if issues:
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("  ✅ No potential issues were identified.")
    
    print("="*50 + "\n")

def save_json_report(stats: Dict[str, Any], issues: List[str], filename: str = 'report.json'):
    """Saves the analysis statistics and issues to a JSON file."""
    
    report_data = {
        'analysis_summary': stats,
        'potential_issues': issues
    }
    
    try:
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        print(f"📄 JSON report successfully saved to '{filename}'.")
    except IOError as e:
        print(f"❌ Error: Could not save JSON report to '{filename}'. Reason: {e}")

# --- Utility Functions ---

def generate_test_log(filename: str = 'access.log', lines: int = 200):
    ip_addresses = [
        '203.0.113.15', '198.51.100.22', '192.0.2.8', '88.120.45.67',
        '104.248.63.11', '45.79.12.34', '172.68.142.99', '66.249.75.4',
        '216.58.204.14', '1.1.1.1', '192.168.1.100'
    ]
    special_ip = '89.160.19.113'
    paths = [
        '/login', '/logout', '/products', '/products/item/123', '/cart',
        '/api/v1/users', '/api/v1/data', '/assets/style.css',
        '/assets/script.js', '/images/logo.png', '/about-us'
    ]
    methods = ['GET', 'POST']
    status_codes = [200, 301, 404, 500, 403]
    status_weights = [0.70, 0.10, 0.12, 0.05, 0.03]
    log_ips = [special_ip] * 25
    remaining_lines = lines - len(log_ips)
    if remaining_lines > 0:
        log_ips.extend(random.choices(ip_addresses, k=remaining_lines))
    random.shuffle(log_ips)
    with open(filename, 'w') as f:
        now = datetime.now()
        for i in range(lines):
            ip = log_ips[i]
            timestamp_dt = now - timedelta(seconds=(lines - i) * random.randint(5, 30))
            timestamp_str = timestamp_dt.strftime('%d/%b/%Y:%H:%M:%S %z')
            method = random.choice(methods)
            path = random.choice(paths)
            status = random.choices(status_codes, weights=status_weights)[0]
            size = random.randint(50, 9000)
            log_line = f'{ip} - - [{timestamp_str}] "{method} {path} HTTP/1.1" {status} {size}\n'
            f.write(log_line)
    print(f"✅ Successfully generated '{filename}' with {lines} lines.")

# --- Main Execution Block ---

if __name__ == '__main__':
    log_file_name = 'access.log'
    json_report_name = 'analysis_report.json'
    
    # 1. Generate fresh test data
    generate_test_log(filename=log_file_name, lines=500)
    
    # 2. Analyze the log file
    analysis_results = analyze_log_file(log_file_name)

    if analysis_results:
        # 3. Identify potential issues from the analysis
        detected_issues = identify_issues(analysis_results)
        
        # 4. Present the findings using the new reporting functions
        print_console_report(analysis_results, detected_issues)
        save_json_report(analysis_results, detected_issues, filename=json_report_name)