import os
import requests
import time

API_KEY = 'ae472149383907d938bf443c3f36f3dddab444cc06444348c00f42d7ccf87dc9'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'


def scan_file(api_key, file_path):
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            params = {'apikey': api_key}
            response = requests.post(SCAN_URL, files=files, params=params)
            response.raise_for_status()
            return response.json()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except requests.exceptions.RequestException as e:
        print(f"Error scanning file {file_path}: {e}")
    return None


def get_report(api_key, resource):
    try:
        params = {'apikey': api_key, 'resource': resource}
        response = requests.get(REPORT_URL, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving report for {resource}: {e}")
    return None


def scan_for_virus(directory_, infected_files_):
    for name in os.listdir(directory_):
        path = os.path.join(directory_, name)
        if os.path.isfile(path):
            print(f"Scanning {path}...")
            scan_response = scan_file(API_KEY, path)
            if scan_response:
                resource = scan_response.get('resource')
                if resource:
                    # Wait until the scan completes
                    while True:
                        report_response = get_report(API_KEY, resource)
                        if report_response:
                            break
                        time.sleep(5)  # Wait for 5 seconds before checking again

                    positives = report_response.get('positives', 0)
                    if positives > 0:
                        infected_files_.append(path)
                        print(f"Malicious file detected: {path}")
                    else:
                        print(f"No threats found in {path}")
                else:
                    print(f"Failed to get resource for {path}")
        elif os.path.isdir(path):
            scan_for_virus(path, infected_files_)


if __name__ == "__main__":
    directory = input("Enter wanted directory: ")
    if os.path.isdir(directory):
        infected_files = []
        scan_for_virus(directory, infected_files)
        if not infected_files:
            print("No malicious files detected.")
        else:
            print("List of malicious files:")
            for infected_file in infected_files:
                print(infected_file)
    else:
        print(f"{directory} is not a valid directory")
