import re
import csv
from collections import Counter, defaultdict

# Define constants
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Reads the log file and returns parsed log entries."""
    log_entries = []
    with open(file_path, "r") as file:
        for line in file:
            log_entries.append(line.strip())
    return log_entries

def count_requests_per_ip(log_entries):
    """Counts requests made by each IP address."""
    ip_counts = Counter()
    for entry in log_entries:
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", entry)
        if ip_match:
            ip_counts[ip_match.group(1)] += 1
    return ip_counts

def most_frequently_accessed_endpoint(log_entries):
    """Identifies the most frequently accessed endpoint."""
    endpoint_counts = Counter()
    for entry in log_entries:
        endpoint_match = re.search(r'"(?:GET|POST) (/\S*) HTTP', entry)
        if endpoint_match:
            endpoint_counts[endpoint_match.group(1)] += 1
    if endpoint_counts:
        most_accessed = endpoint_counts.most_common(1)[0]
        return most_accessed
    return None

def detect_suspicious_activity(log_entries, threshold):
    """Detects suspicious activity based on failed login attempts."""
    failed_logins = Counter()
    for entry in log_entries:
        if "401" in entry or "Invalid credentials" in entry:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", entry)
            if ip_match:
                failed_logins[ip_match.group(1)] += 1
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}
    return suspicious_ips

def save_to_csv(ip_requests, most_accessed, suspicious_activity, output_file):
    """Saves the analysis results to a CSV file."""
    with open(output_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        
        # Write IP request counts
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        writer.writerow([])  # Blank line for separation
        
        # Write most accessed endpoint
        writer.writerow(["Most Accessed Endpoint"])
        if most_accessed:
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed[0], most_accessed[1]])
        else:
            writer.writerow(["No data found"])
        
        writer.writerow([])  # Blank line for separation
        
        # Write suspicious activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def display_results(ip_requests, most_accessed, suspicious_activity):
    """Displays the analysis results in the terminal."""
    print("Requests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count:<15}")
    print()
    
    print("Most Frequently Accessed Endpoint:")
    if most_accessed:
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    else:
        print("No data found")
    print()
    
    print("Suspicious Activity Detected:")
    if suspicious_activity:
        print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count:<25}")
    else:
        print("No suspicious activity detected.")
    print()

def main():
    log_entries = parse_log_file(LOG_FILE)
    
    # Count requests per IP
    ip_requests = count_requests_per_ip(log_entries)
    
    # Find most frequently accessed endpoint
    most_accessed = most_frequently_accessed_endpoint(log_entries)
    
    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_entries, FAILED_LOGIN_THRESHOLD)
    
    # Display results
    display_results(ip_requests, most_accessed, suspicious_activity)
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_activity, OUTPUT_CSV)

if __name__ == "__main__":
    main()
