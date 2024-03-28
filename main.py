import re
import sys

class LogAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path

    def read_logs(self):
        try:
            with open(self.file_path, 'r') as file:
                logs = file.readlines()  # Read all lines from the log file
            return logs
        except FileNotFoundError:
            print(f"Error: File '{self.file_path}' not found.")
            sys.exit(1)  # Exit the program if the file is not found
        except Exception as e:
            print(f"Error reading logs: {e}")
            sys.exit(1)  # Exit the program if there's an error reading the logs

    def parse_log_entry(self, log_entry):
        # Regular expression pattern to parse log entries
        pattern = r'\[(.*?)\] (\d+\.\d+\.\d+\.\d+) ([A-Z]+) (.*?) (\d+) "(.*?)"'
        match = re.match(pattern, log_entry)  # Match the pattern with the log entry
        if match:
            # Extract different parts of the log entry
            timestamp, source_ip, http_method, url, status_code, user_agent = match.groups()
            return {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'http_method': http_method,
                'url': url,
                'status_code': status_code,
                'user_agent': user_agent
            }
        else:
            return None  # Return None if the log entry doesn't match the pattern

    def detect_failed_login(self, log_entry):
        return log_entry['status_code'] == '401'  # Check if the status code indicates a failed login

    def analyze_logs(self, logs):
        suspicious_logs = []
        for log_entry in logs:
            parsed_log_entry = self.parse_log_entry(log_entry)  # Parse each log entry
            if parsed_log_entry and self.detect_failed_login(parsed_log_entry):
                suspicious_logs.append(parsed_log_entry)  # Add suspicious log entries to the list
        return suspicious_logs

    def generate_alerts(self, suspicious_logs):
        if suspicious_logs:
            print("Suspicious activity detected:")
            for log_entry in suspicious_logs:
                # Print details of suspicious log entries
                print(f"Timestamp: {log_entry['timestamp']}, Source IP: {log_entry['source_ip']}, "
                      f"HTTP Method: {log_entry['http_method']}, URL: {log_entry['url']}, "
                      f"Status Code: {log_entry['status_code']}, User Agent: {log_entry['user_agent']}")
        else:
            print("No suspicious activity detected.")

if __name__ == "__main__":
    file_path = 'access.log'  # Replace with the path to your log file
    log_analyzer = LogAnalyzer(file_path)
    logs = log_analyzer.read_logs()  # Read logs from the log file
    suspicious_logs = log_analyzer.analyze_logs(logs)  # Analyze logs for suspicious activity
    log_analyzer.generate_alerts(suspicious_logs)  # Generate alerts for suspicious activity
