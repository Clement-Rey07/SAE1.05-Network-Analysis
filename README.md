User Guide: Network Traffic Analyzer (SAE 1.05)
1. Overview
This tool is designed to analyze network traffic logs (dump.txt) to identify security threats, specifically Denial of Service (DoS) attacks. It parses the logs, identifies suspicious IP addresses, and generates a comprehensive security report.
2. Prerequisites
Before running the script, ensure you have the following installed on your machine:
    • OS: Windows 10/11
    • Software: Python 3.x
    • Libraries: matplotlib and markdown
        ◦ To install them, run: pip install matplotlib markdown
3. Project Structure
Place all files in the same folder (e.g., on your Desktop):
    • programme_analyse.py: The main Python script.
    • dump.txt: The raw network logs (tcpdump format).
    • analyse_reseau.csv: The output data for Excel analysis.
4. How to Run the Analysis
    1. Open your terminal or command prompt.
    2. Navigate to the folder containing the files.
    3. Run the script:
       Bash
       py programme_analyse.py
    4. The script will automatically detect the attacker and generate the reports.
5. Generated Results
    • Rapport_Security.html: A web report with statistics and evidence.
    • graphique_attaques.png: A chart showing traffic volume per IP.
    • analyse_reseau.csv: Raw data ready for spreadsheet software.
6. Using the Spreadsheet (Excel / LibreOffice)
To perform a manual check:
    1. Open LibreOffice Calc or Excel.
    2. Open analyse_reseau.csv.
    3. Important: In the import window, select Semicolon (;) as the separator.
    4. Select all data (Ctrl+A) and insert a Pivot Table (Tableau Croisé Dynamique).
    5. Drag the Source field into both Row Fields and Data Fields.
    6. Create a Pie Chart to visualize the attack source.
