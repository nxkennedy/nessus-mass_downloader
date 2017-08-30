#!/usr/bin/env ruby
#################################################################################################
# Name: Nessus Mass Report Downloader 
# Author: Nolan Kennedy (nxkennedy)
# ** BASED ON THE NESSUS 6 REPORT DOWNLOADER by Travis Lee **
#
# Description:  Script that connects to a specified Nessus 6 server using the
#		Nessus REST API to automate mass report downloads. It automagically downloads
#	 	reports for all scans in .nessus, .csv, and .pdf formats and saves them to a local
#		folder.
#
# Usage: ruby nessus-mass_downloader.rb
#
# Reference: https://<nessus-server>:8834/api
#
#################################################################################################

require 'net/http'
require 'fileutils'
require 'io/console'
require 'date'
require 'json'
require 'openssl'
require 'logger'




# Load config file
cfg_path = "config/config.json"

unless File.file?(cfg_path) # if config file does not exist

	if File.file?("config/config.json.example") # but the example file exists
		raise "\n\n[!] ERROR: RENAME 'config.json.example' TO 'config.json'\n[!] Ensure 'config.json' contains the required info\n\n"
	else
		raise "\n\n[!] FATAL ERROR: NO CONFIG FILE FOUND.\n[!] Please see documentation for details.\n\n"
	end

end

cfg_file = File.read(cfg_path)
config = JSON.parse(cfg_file)

# Log file
log_path = config["file-paths"]['logs']
unless File.directory?(log_path)
	FileUtils.mkdir_p(log_path)
end

# dest folder for reports
rpath = config["file-paths"]['dest_folder']
unless File.directory?(rpath)
	FileUtils.mkdir_p(rpath)
end

$LOG = Logger.new("#{log_path}/alerts.log", "daily")
$DEBUG = false
$VERBOSE = false

# a flashy spinner used to show us progress
$SPINNER = Enumerator.new do |e|
	loop do
		e.yield '|'
		e.yield '/'
		e.yield '-'
		e.yield '\\'
	end
end

# we'll use this to calculate finish times
def time_calc(start, finish)
	time = finish - start
	if time >= 60.0
		time = (time / 60.0).round(2).to_s
		return  time + " min"
	else
		return time.round(2).to_s + " sec"
	end
end

# This function downloads the nessus and csv reports from each server
def report_download(http, headers, nserver, reports, rpath)
	begin
		puts "\nDownloading reports from #{nserver}. Please wait..."

		# see which file types to download
		filetypes_to_dl = ["nessus", "csv", "pdf"]

		# chapters for pdf
		chapters = "vuln_hosts_summary;vuln_by_plugin;vuln_by_host;remediations;compliance_exec;compliance;"

		# iterate through all the indexes and download the reports
		reports["scans"].each do |rep|
			name = rep["name"].split.join("_")
			date = DateTime.strptime(rep["last_modification_date"].to_s,'%s').strftime('%Y%m%d-%H%M')

			# Only download reports for completed scans
			if rep["status"] != "completed"
				$LOG.warn "#{nserver}: Skipped download: #{rep["name"]}. Scan status: '#{rep["status"]}' != 'completed'"
				puts "\n\n[!] WARNING #{nserver}: Skipping download of '#{rep["name"]}' because of '#{rep["status"]}' status.\n"
			else
				rep_id = rep["id"].to_s.strip
				filetypes_to_dl.each do |ft|

					# export report
					puts "\n[+] Exporting scan report for: " + name + ", type: " + ft if $VERBOSE
					path = "/scans/" + rep_id + "/export"

					if ft == "pdf"
						data = {'format' => ft, 'chapters' => chapters, 'password' => ""}
					else
						data = {'format' => ft, 'chapters' => "", 'password' => ""}
					end

					@time1 = Time.now
					resp = http.post(path, data.to_json, headers)
					fileid = JSON.parse(resp.body)

					# check export status
					status_path = "/scans/" + rep_id + "/export/" + fileid["file"].to_s + "/status"

					loop do
						printf("\r[+] Generating report in Nessus... %s", $SPINNER.next) if $VERBOSE
						status_resp = http.get(status_path, headers)
						status_result = JSON.parse(status_resp.body)
						break if status_result["status"] == "ready"
					end
					print "\r[+] Generating report in Nessus... DONE!\r" if $VERBOSE

					# download report
					print "[+] Downloading report...                 \r" if $VERBOSE
					sleep(1) if $VERBOSE
					dl_path = "/scans/" + rep_id + "/export/" + fileid["file"].to_s + "/download"

					### debug ###
					response_start = Time.now if $DEBUG

					dl_resp = http.get(dl_path, headers)

					response_end = Time.now if $DEBUG

					if $DEBUG
						puts "\n==== START DEBUGGING INFO ===="
						puts "HTTP Response Time: #{(response_end - response_start).round(2)}"
						$LOG.debug "HTTP Response Time: #{(response_end - response_start).round(2)}"
						puts "HTTP Response Code: #{dl_resp.code}"
						$LOG.debug "HTTP Response Code: #{dl_resp.code}"
						puts "HTTP Response Size: #{dl_resp.content_length} bytes"
						$LOG.debug "HTTP Response Size: #{dl_resp.content_length}"
						puts "==== END DEBUGGING INFO ====\n"
					end
					### end debug ###

					print "[+] Downloading report... DONE!           \r" if $VERBOSE
					sleep(1) if $VERBOSE
					# create final path/filename and write to file
					fname = "#{name}_#{date}.#{ft}"
					fpath = "#{rpath}/#{name}_#{date}.#{ft}"

					# write file
					open(fpath, 'w') { |f|
						print "[+] Writing report to file...         \r" if $VERBOSE
						sleep(1) if $VERBOSE
						f.puts dl_resp.body
	  				}
					print "[+] Writing report to file... DONE!        \r" if $VERBOSE
					sleep(1) if $VERBOSE
	  				puts "[+] Report saved as: #{fname}" if $VERBOSE
					@time2 = Time.now
					puts "[+] Time elapsed: #{time_calc(@time1, @time2)}" if $VERBOSE
				end
  			end
		end

	rescue StandardError => download_report_error
		$LOG.error "#{nserver}: Error downloading report: #{download_report_error}"
		puts "\n\n[!] ERROR #{nserver}: Error downloading report: #{download_report_error}\n\n"

	end
end

# This method will return a list of all the reports on the server
def get_report_list(http, headers, nserver)
	begin

		# retrieve scan info
		path = "/scans"
		resp = http.get(path, headers)
		results = JSON.parse(resp.body)

		# pretty table formatting for terminal window
		printf("\n%-7s %-50s %-30s %-15s\n", "Scan ID", "Name", "Last Modified", "Status") if $VERBOSE
		printf("%-7s %-50s %-30s %-15s\n", "-------", "----", "-------------", "------") if $VERBOSE

		# print out all the reports
		results["scans"].each do |scan|
			printf("%-7s %-50s %-30s %-15s\n", scan["id"], scan["name"], DateTime.strptime(scan["last_modification_date"].to_s,'%s').strftime('%b %e, %Y %H:%M %Z'), scan["status"]) if $VERBOSE
		end

		return results

	rescue StandardError => get_scanlist_error
		$LOG.error "#{nserver}: Error getting scan list: #{get_scanlist_error}"
		puts "\n\n[!] ERROR #{nserver}: Error getting scan list: #{get_scanlist_error}\n\n"
	end
end

# This method will make the initial login request and set the token value to use for subsequent requests
def get_token(http, nserver, username, password)
	begin
		path = "/session"
		data = {'username' => username, 'password' => password}
		resp = http.post(path, data.to_json, 'Content-Type' => 'application/json')
		token = JSON.parse(resp.body)
		headers = {
			"User-Agent" => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0',
			"X-Cookie" => 'token=' + token["token"],
			"Accept" => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			"Accept-Language" => 'en-us,en;q=0.5',
			"Accept-Encoding" => 'text/html;charset=UTF-8',
			"Cache-Control" => 'max-age=0',
			"Content-Type" => 'application/json'
		 }
		return headers

	rescue StandardError => get_token_error
		$LOG.error "#{nserver}: Error logging in/getting token: #{get_token_error}"

		if get_token_error.message == "no implicit conversion of nil into String"
			puts "\n\n[!] ERROR #{nserver}: Error logging in/getting token: wrong username or password\n"
		else
			puts "\n\n[!] ERROR #{nserver}: Error logging in/getting token: #{get_token_error}\n"
		end

		return false
	end
end

### MAIN ###

# Clears the terminal and prints our shmexy banner
print "\e[2J\e[f"
banner = <<EOB


::::    ::: ::::    ::::  :::::::::
:+:+:   :+: +:+:+: :+:+:+ :+:    :+:
:+:+:+  +:+ +:+ +:+:+ +:+ +:+    +:+
+#+ +:+ +#+ +#+  +:+  +#+ +#+    +:+    -> NESSUS MASS DOWNLOADER  v1.1.0
+#+  +#+#+# +#+       +#+ +#+    +#+    -> Author: nxkennedy
#+#   #+#+# #+#       #+# #+#    #+#
###    #### ###       ### #########


EOB
puts banner

# print usage if the user needs it
USAGE = <<ENDUSAGE

[+] No args required!
[+] Usage:
		ruby nessus-mass_downloader.rb

-h, --help  	prints usage to terminal
-v, --verbose	prints verbose output to terminal
-d, --debug  	prints debugging/troubleshooting information to window and log file

ENDUSAGE

ARGV.each do |arg|
	case arg
	when "-h", "--help"
			puts USAGE
			exit
		when "-v", "--verbose"
			$VERBOSE = true
		when "-d", "--debug"
			$VERBOSE = true
			$DEBUG = true
			puts "\n[$] SCRIPT IS NOW IN DEBUGGING MODE"
			puts "[$] ALL DEBUGGING OUTPUT WILL BE SAVED TO '#{log_path}/alerts.log'"
		else
			puts "[!] ERROR: '#{arg}' is not a valid arg for this script!"
			puts USAGE
			exit
	end
end
# list of servers
nservers = config["nessus"]["servers"]

# nessus port
nserverport = config["nessus"]["port"]

# Collect user/pass info
print "\nEnter your Nessus Username: "
username = STDIN.gets.chomp.to_s
print "Enter your Nessus Password (will not echo): "
password = STDIN.noecho(&:gets).chomp.to_s

# start timer for performance tracking
timer1 = Time.now

# now attempt to auth with each server
nservers.each do |nserver|
	@timer1 = Time.now
	begin
		# https object
		http = Net::HTTP.new(nserver, nserverport)
		# Long timeouts required for shabby connections
		http.open_timeout = 120
		http.read_timeout = 300
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE

		# login and get token cookie
		headers = get_token(http, nserver, username, password)

		# if failed login, move to next host in list
		unless headers
			next
		end

		# get list of reports
		puts "\n\nGetting report list from #{nserver}..."
		reports = get_report_list(http, headers, nserver)

		if reports.count == 0
			$LOG.error "#{nserver}: Error! There are no reports to download!"
			puts "\n\n[!] ERROR #{nserver}: Error! There are no reports to download!\n\n"
		end

		# run report download
		report_download(http, headers, nserver, reports, rpath)

	# not the best practice for exceptions, I know. But we need to keep moving.
	rescue Exception => e
		puts e
		next
	end
	@timer2 = Time.now
	puts "\n==="
	puts "[*] SUCCESS: Download from #{nserver} complete! (#{time_calc(@timer1, @timer2)})"
	puts "==="
end
timer2 = Time.now

success_str = "[*] SUCCESS: Report Download Phase Complete for All Servers! (#{time_calc(timer1, timer2)})"
outline = "*" * success_str.length()
puts "\n" + outline
puts success_str
puts outline + "\n\n"
