#!/usr/bin/python
# Script to assist with BlueCat querying.
# Created by Brett Gross.

import requests, json, re, argparse, sys, os
from netaddr import IPNetwork,IPAddress,AddrFormatError

try:
	from requests.packages.urllib3.exceptions import InsecureRequestWarning
	requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except (ImportError):
	pass

def get_file_contents(file_path):
	file_contents = []
	if os.path.exists(file_path):
		with open(file_path) as f:
			file_contents = f.read().splitlines()
	file_contents = [item.strip() for item in file_contents]
	if len(file_contents) < 1:
		print("Error: Provided file appears empty.")
		exit()

	return file_contents


class BlueViewReq(object):
	def __init__(self, query):
		self.results = {}
		self.original_query = self.query = query
		self.url = "BlueView-Hostname"

		if self.query.startswith("/") or os.path.exists(self.query):
			self.query = get_file_contents(query)
			self.results =  {k:[] for k in self.query}
		else:
			self.query = [query]
			self.results[query] = []
			print("Query: '%s'" % self.original_query)
		 
		self.response_data = {k:None for k in self.results.keys()}
		self.start_session()
		

	def start_session(self):
		self.session = requests.Session()
		self.session.trust_env = False
		self.session.post("https://%s/login" % self.url, data={"username":"shittyuser", "password":"shittypassword","login-btn":"","url_hit":""}, proxies={"https":None}, verify=False, allow_redirects=True)

	def replace_wildcard_input(self):
		modified_query = []
		for item in self.query:
			modified_query.append(item.replace(":", "%25").replace("*", "%25"))
		self.query = modified_query

	def pull_results(self):
		self.query_method()
		self.parse_method()

	def print_results(self):
		if self.results:
			print("")
			print(self.results["header"])
			for query, result in self.results.iteritems():
				if "header" not in query and len(result) > 0:
					query = query.replace("%25", "*")
					print("%s" % "\n".join(result))
				
	def write_results(self, report_name="/tmp/output.txt"):
		if not os.path.isfile(report_name):
			with open(report_name, "w") as outfile:
				outfile.write("%s\n" % self.results["header"])
				for query, result in self.results.iteritems():
					if "header" not in query and len(result) > 0:
						outfile.write("%s\n" % "\n".join([r.encode("utf-8") for r in result]))
		else:
			print("\nError: '%s' already exists." % report_name)
			exit()

class BlueViewName(BlueViewReq):
	def __init__(self, query):
		BlueViewReq.__init__(self, query)
		self.replace_wildcard_input()
		self.results = {k:[] for k in self.query}
		self.response_data = {k:None for k in self.query}
		self.results["header"] = "%-30s\t%s" % ("Name","IP_Address")

	def query_method(self):
		for query in self.query:
			answer = self.session.get("https://%s/BlueView2/sqlfindname/%s" % (self.url, query), proxies={"https":None}, verify=False, allow_redirects=True)

			if "200" not in str(answer.status_code):
				print("An error occurred during request.\nTry making the query smaller or more specific.")
				self.results[query].append("<error on response>")
				continue

			self.response_data[query] = json.loads(answer.text)["data"]

	def parse_method(self):
		for query in self.query:
			hostname = host_ip = "-"
			for line in self.response_data[query][0]:
				if "resourcerecord" in line:
					hostname = re.findall('resourcerecord/\d+">[^<]+', line)[0].split(">")[-1]
				elif "ip4address" in line:
					host_ip = re.findall('ip4address/\d+">[^<]+', line)[0].split(">")[-1]


			self.results[query].append("%-30s\t%s" % (hostname, host_ip))


class BlueViewIP(BlueViewReq):
	def __init__(self, query):
		BlueViewReq.__init__(self, query)
		self.results["header"] = "%-10s\t%-55s\t%-10s\t%-10s\t%-10s" % ("IP_Address", "Hostname", "Mac_Address", "Comment", "State") 
		
	def query_method(self):
		bad_queries = set()
		for query in self.query:
			try:
				IPAddress(query)
			except AddrFormatError:
				self.results[query].append("<error ip_address format>")
				print("Error: The supplied IP Address '%s' appears to be invalid." % query)
				bad_queries.add(query)
				continue
			
			answer = self.session.post("https://%s/BlueView2/form" % self.url, data={"ipsearch":query,"searchip":"Search"})
			if "200" not in str(answer.status_code):
				self.results[query].append("<error on response>")
				print("An error occurred during request.\nTry making the query smaller or more specific.")
				continue

			self.response_data[query] = answer.text

		for query in bad_queries:
			self.query.pop(self.query.index(query))
			self.results.pop(query)
			self.response_data.pop(query)

	def parse_method(self):	
		for query in self.query:
			hostname = "<no results>"
			matches = re.findall("BlueView2/ip4address[^\n]+", self.response_data[query])
			if matches:
				for match in matches:
					resource_records = [match.strip("/") for match in re.findall('/\d+', match)]
					for record in resource_records:
						answer = self.session.get("https://%s/BlueView2/ip4address/%s" % (self.url, record))
						
						if "200" not in str(answer.status_code):
							self.results[query].append("<error on response>")
							print("An error occurred during request.\nTry making the query smaller or more specific.")
							continue

						hostname = mac_addr = comment = device_state = "-"
						try:
							hostname = re.findall('resourcerecord/\d+">[^<]+', answer.text)[0].split(">")[-1]
						except (IndexError):
							pass
						try:
							mac_addr = re.findall("macAddress</td><td>[^<]+", answer.text)[0].split("<td>")[-1]
							comment = re.findall("Comment</td><td>[^<]+", answer.text)[0].split("<td>")[-1]
							device_state = re.findall("State</td><td>[^<]+", answer.text)[0].split("<td>")[-1]
						except (IndexError):
							pass

						self.results[query].append("%-10s\t%-55s\t%-10s\t%-10s\t%-10s" % (query,hostname,mac_addr,comment,device_state))

class BlueViewCIDR(BlueViewReq):
	def __init__(self, query):
		BlueViewReq.__init__(self, query)
		self.results["header"] = "%s\t%s" % ("IP_Address", "Name")	

	def query_method(self):
		bad_queries = set()
		for query in self.query:
			try:
				IPNetwork(query)
			except AddrFormatError:
				self.results[query].append("<error cidr format>")
				print("Error: CIDR '%s' supplied appears to be invalid." % query)	
				bad_queries.add(query)
				continue

			answer = self.session.post("https://%s/BlueView2/form" % self.url, data={"ipsearch":query,"searchip":"Search"})
			if "200" not in str(answer.status_code):
				self.results[query].append("<error on response>")
				print("An error occurred during request.\nTry making the query smaller or more specific.")
				continue

			self.response_data[query] = answer.text

		for query in bad_queries:
			self.query.pop(self.query.index(query))
			self.results.pop(query)
			self.response_data.pop(query)
	
	def parse_method(self):
		for query in self.query:
			ip_address = dns_name = "<no_results>"
			if self.response_data[query].find("ip4network") > 0:
				ip4_response_url = "ip4network"
				ip4_lookup_url = "sqlnetwork"	
			elif self.response_data[query].find("ip4block") > 0:
				ip4_response_url = "ip4block"
				ip4_lookup_url= "getnb"			
			else:
				self.results[query].append("<error parsing response>")
				print("Error parsing BlueViewCIDR HTTP response.")
				continue

			matches = re.findall("/BlueView2/%s[^\n]+" % ip4_response_url, self.response_data[query])
			if matches:
				for match in matches:
					resource_record = re.findall("(?i)blueview2/%s/[0-9]+" % ip4_response_url, match)[0].split("/")[-1]
					answer = self.session.get("https://%s/BlueView2/%s/%s" % (self.url, ip4_lookup_url, resource_record))

					if "200" not in str(answer.status_code):
						self.results[query].append("<error on response>")
						print("An error occurred during request.\nTry making the query smaller or more specific.")
						continue

					cidr_results = json.loads(answer.text)["data"]
					for result in cidr_results:
						# Some results contain the ip_address.
						ip_address = result[1]
						# Some results contain extra info, further parsing required for ip_address extraction.
						if "/" in result[1]: ip_address = result[1].split(">")[1].split("<")[0]
						if result[2]:
							dns_name = result[2]
							try:
								if "/" in result[2]: dns_name = result[2].split(">")[1].split("<")[0]
							# Can't recall what the data looked like.
							# Wrapping in try/except because lazy.
							except (IndexError):
								pass
						else:
							dns_name = "-"

						self.results[query].append("%s\t%s" % (ip_address, dns_name))

class BlueViewMAC(BlueViewReq):
	def __init__(self, query):
		BlueViewReq.__init__(self, query)		
		self.results["header"] = "%-20s\t%s" % ("Mac_Address", "IP_Address")

	def query_method(self):
		for query in self.query:
			answer = self.session.get("https://%s/BlueView2/findmac/%s" % (self.url, query), proxies={"https":None}, verify=False, allow_redirects=True)
			if "200" not in str(answer.status_code):
				self.results[query].append("<error on response>")
				print("An error occurred during request.\nTry making the query smaller or more specific.")
				continue

			self.response_data[query] = answer.text

	def parse_method(self):
		for query in self.query:
			matches = re.findall("BlueView2/ip4address[^\n]+", self.response_data[query])
			if matches:
				for match in matches:
					ip = re.findall("[0-9]{2,}\.[0-9]{2,}\.[0-9]{2,}\.[0-9]{2,}", match)[0]
					self.results[query].append("%-20s\t%s" % (query, ip))

class BlueViewSite(BlueViewReq):
	def __init__(self, query):
		BlueViewReq.__init__(self, query)
		self.results["header"] = "%-30s\t%-65s\t%-25s\t%-20s\t%-10s" % ("Site_Range", "Description", "Site_Name", "Site_City", "Site_State")

	def query_method(self):
		for query in self.query:
			answer  = self.session.get("https://%s/BlueView2/searchsiteid/%s" % (self.url, query))
			if "200" not in str(answer.status_code):
				self.results[query].append("<error on response>")
				print("An error occurred during request.\nTry making the query smaller or more specific.")
				continue

			self.response_data[query] = json.loads(answer.text)["data"]

	def parse_method(self):
		for query in self.query:
			for line in self.response_data[query]:
				site_range = re.findall(">[^<]+", line[1])[0].strip(">")
				site_description = line[2]
				site_name = line[4]
				site_city = line[7]
				site_state = line[8]
				self.results[query].append("%-30s\t%-65s\t%-25s\t%-20s\t%-10s" % (site_range, site_description, site_name, site_city, site_state))

			
					
def process_args():
	parser = argparse.ArgumentParser(description='Bluecat DNS and IP Address lookup.')
	parser.add_argument('--name', metavar="<dns_name>", type=str, help='DNS/Host name (or file of names) to lookup. You can use "*" as a wildcard operator when wrapped in quotes.')
	parser.add_argument('--ip_addr', metavar="<ip_address>", type=str, help='IP Address (or file of IPs) to lookup.')
	parser.add_argument('--mac_addr', metavar="<mac_addr>", type=str, help='MAC Address (or file of MACs) to IP Address.')
	parser.add_argument('--cidr', metavar="<cidr>", type=str, help='CIDR (or file of CIDRs) to lookup')
	parser.add_argument('--site', metavar="<site_code>", type=str, help='Site (or file of site) code to lookup')
	parser.add_argument('--out', metavar="<output_filename>", type=str, help='Save output to file.')
	return parser.parse_args()
	

def main():
	opts = process_args()

	if opts.ip_addr:
		blueview_req = BlueViewIP(opts.ip_addr)
	elif opts.name:			
		blueview_req = BlueViewName(opts.name)
	elif opts.mac_addr:
		blueview_req = BlueViewMAC(opts.mac_addr)
	elif opts.cidr:
		blueview_req = BlueViewCIDR(opts.cidr)
	elif opts.site:
		blueview_req = BlueViewSite(opts.site)

	try:
		blueview_req.pull_results()
		blueview_req.print_results()

		if opts.out:
			blueview_req.write_results(opts.out)
	
	except NameError:
		print("Error: Try running '%s --help'" % sys.argv[0])
		exit()

if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt):
        print("^C")
        exit()
