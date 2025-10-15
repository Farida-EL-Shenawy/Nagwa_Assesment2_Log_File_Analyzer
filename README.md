# 📊 Log File Analyzer
A powerful and efficient Python command-line tool designed to parse and analyze web server log files. This script provides DevOps and engineering teams with a high-level summary of web traffic, identifies potential issues, and generates actionable reports.


## ✨ Key Features
Efficient Parsing: Uses a pre-compiled regular expression to quickly and accurately parse standard Apache/Nginx log formats.

Comprehensive Statistics: Generates key metrics including:

Total Request Count

Status Code Breakdown (2xx, 3xx, 4xx, 5xx)

Top 5 Most Active IP Addresses

Top 5 Most Requested Endpoints

Intelligent Issue Detection: Automatically flags potential problems like High Error Rates and Suspicious IP Activity.

Dual Reporting: Outputs a beautifully formatted summary to the console and a structured report to a JSON file.

# ⭐ Bonus Feature: IP Geolocation
To provide deeper, more actionable insights, this tool includes a valuable bonus feature:

Geographical Context: For every IP address flagged as "suspicious," the script makes a live API call to geolocate it. The report then includes the IP's city and country, helping teams to quickly identify the origin of unusual traffic patterns (e.g., "Location: Mountain View, United States").

## 🛠️ Tech Stack
Language: Python 3.13

Core Libraries: re (for Regex), json, datetime

External Packages: requests (for the IP Geolocation bonus feature)

## 🚀 Quick Start Guide
This project requires Python 3.13.

1. Set Up The Project
Clone or download the repository, then open your terminal and navigate into the log_analyzer directory.

       cd path/to/log_analyzer

2. Create and Activate the Virtual Environment
On Windows:

       py -3.13 -m venv .venv
       .venv\Scripts\activate

On macOS / Linux:

    python3.13 -m venv .venv
    source .venv/bin/activate

3. Install Dependencies
Install the required requests package.

       pip install -r requirements.txt

▶️ How to Run the Script
Once setup is complete, simply run the script from your terminal:


       python analyze_logs.py


