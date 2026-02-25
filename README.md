cat << 'EOF' > README.md
# GCP Bucket Scanner: Unauthenticated GCS Object Tally

### The Background
This project was born out of a realization that relying on a Cloud Console can be a bottleneck. While working through a massive dataset, I found the 100-object-per-page UI limit to be insufficient for high-level data auditing. This script extrapolates a simple inventory logic into a robust Python tool that performs unauthenticated scans of public Google Cloud Storage buckets.

### The Problem
When auditing public AI datasets or large-scale buckets, the GCS Console:
* Limits visibility to 100 objects per page.
* Makes it difficult to calculate total storage size across thousands of files.
* Requires manual interaction for data that should be programmatically accessible.

### The Solution
This script uses the GCS XML API to paginate through public buckets without requiring local authentication. It provides:
* Full object counts and total byte-size calculations.
* A breakdown of data by file extension.
* Automated reporting with timestamped text files.
* ANSI color-coded terminal output for readability.

### Technical Overview
* **Language:** Python 3
* **Libraries:** `requests`
* **Method:** Iterative pagination using `continuation-tokens` to bypass the 1000-key limit per request.

### Installation and Usage
To get started, clone the repository using `git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git` and navigate into the directory with `cd YOUR_REPO_NAME`. Install the necessary dependencies by running `pip install requests urllib3`. Before executing the scanner, ensure you have a file named `buckets.txt` in the root directory containing the names of the target buckets (one per line). Finally, run the scanner using the command `python3 gcp_bucket_scanner.py`. The script will output the results to the terminal and generate a timestamped text report automatically.
EOF