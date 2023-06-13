# VirusTotal Project
This is a command-line tool that allows you to check the reputation and analysis results of URLs using the VirusTotal API.

Prerequisites
Before running the tool, make sure you have the following:

Python 3.x installed
VirusTotal API key (required for accessing the API)
Getting Started
Clone the repository:

shell
Copy code
git clone https://github.com/YaelBenYair/virus_total_project.git
Install the required dependencies:

shell
Copy code
pip install -r requirements.txt
Set up the VirusTotal API key:

Create an account on VirusTotal if you don't have one.

Obtain your VirusTotal API key.

Set the API key as an environment variable named VT_API.

shell
Copy code
export VT_API="your_api_key"
Run the main script:

shell
Copy code
python main.py <url> [-s] [-k APIKEY] [-d DAYS]
<url>: The URL you want to scan. You can enter multiple URLs separated by commas without spaces.
-s or --scan: (Optional) Force a new scan of the URL even if it exists in the cache.
-k APIKEY or --apikey APIKEY: (Optional) Specify a different VirusTotal API key for analysis.
-d DAYS or --day DAYS: (Optional) Set the maximum age for URLs in the cache before rescanning (default: 182 days).
View the analysis results for each URL.

Example Usage
shell
Copy code
python main.py http://example.com -s -k your_api_key -d 365
Scan http://example.com with a new analysis (force scan), using a specific API key, and set the maximum cache age to 365 days.
Contributing
Contributions to this project are welcome. If you would like to contribute, please follow these steps:

Fork the repository.
Create a new branch for your contribution.
Make your changes and commit them.
Push your changes to your fork.
Submit a pull request.
Please ensure that your code adheres to the existing coding style and includes appropriate tests.
