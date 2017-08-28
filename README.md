# Nessus Mass Report Downloader


<table>
    <tr>
        <th>Version</th>
        <td>1.1.0</td>
    </tr>
    <tr>
       <th>Author</th>
       <td>Nolan Kennedy (nxkennedy)</td>
    </tr>
    <tr>
        <th>Github</th>
        <td><a href="http://github.com/nxkennedy">http://github.com/nxkennedy</a></td>
    </tr>
</table>

** BASED ON THE NESSUS 6 REPORT DOWNLOADER by Travis Lee **
<br>
This is a point-and-shoot script that connects to specified Nessus servers via REST API to automate mass report downloads.

### Use Case

Automate the download of ALL reports with a scan status of "complete" from single or distributed Nessus servers. Hardcoded formats are .nessus, .csv, and .pdf.

### Requirements
* This was tested and developed against the Nessus 6 API

If running the ruby script:
* ruby >= 2.3.3
* nokogiri

    `gem install nokogiri`

If running the exe, neither ruby nor additional libraries need to be installed before runtime.
* NOTE IF ATTEMPTING TO RECOMPILE THE RUBY SCRIPT: The exe was compiled on windows using OCRA and Ruby 2.3.3. OCRA has issues with versions >2.3.3.


### Usage

1. git clone https://github.com/nxkennedy/nessus-mass_downloader.git
2. cd to wherever your downloaded it
3. update the nessus server list in 'config/config.json.example' and rename the file to 'config.json'
4. the script doesn't require args. In a terminal:

    `ruby nessus-mass_downloader.rb`

    `OPTIONS:`

    `-h, --help  	prints usage to terminal`

    `-v, --verbose	prints verbose output to terminal`

    `-d, --debug  	prints debugging/troubleshooting information to terminal and log file`

5. you will be prompted to enter your nessus creds
6. hit enter and get a cup of coffee while your reports download

### Output
Unless verbose option is set, only brief output is displayed in the terminal as the reports are generated.

* logs/alerts.log: All warnings, errors, and debugging information
* nessus-reports: Directory where reports are saved. Report naming convention is
'scan_name_YYYYMMDD-HHMM.filetype'  (The date/time is when the scan finished, NOT WHEN THE REPORT WAS DOWNLOADED. Makes for easier tracking)
