import os
import shutil
import json
import csv
import re
import time
import sys

# Constant Declaration
REPORT_FILE = "{}_secrets-scan-report_{}.csv"
GIT_REV_LIST_STDOUT = ""
OUTPUT_DIR = "/repo/talisman_html_report"  # Directory to save the CSV report
TALISMAN_REPORT_PATH = "/repo/talisman_html_report/data/report.json"  # Path to the Talisman report

# Function to process the Talisman report and convert it to CSV
def process_talisman_report():
    global REPORT_FILE
    repo_url = os.getenv("REPO_URL")
    if not repo_url:
        if len(sys.argv) < 2:
            print("Repository URL is required")
            exit(1)
        repo_url = sys.argv[1]

    pattern = re.compile("([^/]+)\\.git$")
    matcher = pattern.search(repo_url)
    REPORT_FILE = REPORT_FILE.format(matcher.group(1), int(time.time()))

    CSV_REPORT_FIELDS = ['Type', 'Secret', 'File', 'Commits', 'Author', 'Date Of Commit']
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    with open(TALISMAN_REPORT_PATH, "r") as talismanReportFile, open(os.path.join(OUTPUT_DIR, REPORT_FILE), "w+") as csvReportFile:
        report = json.load(talismanReportFile)
        csvWriter = csv.writer(csvReportFile)
        csvWriter.writerow(CSV_REPORT_FIELDS)

        for result in report["results"]:
            filename = result["filename"]
            if not "package-lock.json" in filename and not "pnpm-lock.yaml" in filename and not "yarn.lock" in filename:
                if "failure_list" in result:
                    for item in result["failure_list"]:
                        row = get_secret_details(item, filename)
                        if len(row) != 0:
                            csvWriter.writerow(row)
                if "warning_list" in result:
                    for item in result["warning_list"]:
                        row = get_secret_details(item, filename)
                        if len(row) != 0:
                            csvWriter.writerow(row)

def get_secret_details(item, filename):
    global GIT_REV_LIST_STDOUT
    commit = ""
    author = ""
    commitDate = ""
    secret = (item["message"])\
        .replace("Potential secret pattern : ","")\
        .replace("Expected file to not contain base64 encoded texts such as: ", "")\
        .replace("Expected file to not contain hex encoded texts such as: ", "")\
        .replace("Expected file to not contain credit card numbers such as: ", "")\
        .strip()
    secret = re.sub(r'\.\.\.$', '', secret)
    secretType = "secret"

    if item["type"] == "filecontent":
        if len(item["commits"]) == 0:
            tmp_secret = secret.replace("\"", "").replace("'", "").replace(",", "").strip()
            if re.match("^[A-Za-z0-9]*$", tmp_secret):
                try:
                    if not GIT_REV_LIST_STDOUT:
                        rev_list_result = subprocess.run(["git", "rev-list", "--all"], capture_output=True, text=True, check=True)
                        GIT_REV_LIST_STDOUT = rev_list_result.stdout.strip().split()
                    grep_result = subprocess.run(["git", "grep", tmp_secret]+ GIT_REV_LIST_STDOUT, capture_output=True, text=True, check=True)
                    head_result = subprocess.run(["head", "-n1"], input=grep_result.stdout, capture_output=True, text=True, check=True)
                    result = subprocess.run(["awk", '{print $1}'], input=grep_result.stdout, capture_output=True, text=True, check=True)
                    results = result.stdout.split()
                    secret = re.sub(r'^.*:', '', head_result.stdout).replace("\n", "")
                    for result in results:
                        resultCommit, resultFile = result.split(':')[:2]
                        if resultFile == filename:
                            commit = resultCommit
                    if not commit:
                        result = subprocess.run(['git', 'show', '-q', commit], capture_output=True, text=True)
                        if result.returncode == 0:
                            resultFields = result.stdout.split("\n")
                            author = resultFields[1].replace("Author:", "").strip()
                            commitDate = resultFields[2].replace("Date:", "").strip()
                except:
                    print("Error Occurred: ", item, filename, file=sys.stderr)
        else:
            commit = item["commits"][-1]
            result = subprocess.run(['git', 'show', '-q', commit], capture_output=True, text=True)
            if result.returncode == 0:
                resultFields = result.stdout.split("\n")
                author = resultFields[1].replace("Author:", "").strip()
                commitDate = resultFields[2].replace("Date:", "").strip()
    elif item["type"] == "filename":
        secretType = "filename"
        secret = filename
        if len(item["commits"]) == 0:
            try:
                log_result = subprocess.run(['git', 'log', '--follow', '--diff-filter=A', '--pretty=format:%H', '--', filename], capture_output=True, text=True, check=True)
                tail_result = subprocess.run(["tail", '-n1'], input=log_result.stdout, capture_output=True, text=True, check=True)
                commit = tail_result.stdout.strip()
                result = subprocess.run(['git', 'show', '-q', commit], capture_output=True, text=True)
                if result.returncode == 0:
                    resultFields = result.stdout.split("\n")
                    author = resultFields[1].replace("Author:", "").strip()
                    commitDate = resultFields[2].replace("Date:", "").strip()
            except:
                print("Error Occurred: ", item, filename, file=sys.stderr)
        else:
            commit = item["commits"][-1]
            result = subprocess.run(['git', 'show', '-q', commit], capture_output=True, text=True)
            if result.returncode == 0:
                resultFields = result.stdout.split("\n")
                author = resultFields[1].replace("Author:", "").strip()
                commitDate = resultFields[2].replace("Date:", "").strip()
    else:
        return []
    
    return [secretType, secret, filename, commit, author, commitDate]

# Main function
def main():
    # Process the Talisman report
    process_talisman_report()

if __name__ == "__main__":
    main()
