import requests
import json
import colorama
from colorama import Fore, Back, Style
import argparse
import sys
import re
import os

class PublicV2VirusTotal:
	def __init__(self):
		self.apikey = "f76bdbc3755b5bafd4a18436bebf6a47d0aae6d2b4284f118077aa0dbdbd76a4"
		self.domainurl="https://www.virustotal.com/vtapi/v2/domain/report"
		self.ipurl="https://www.virustotal.com/vtapi/v2/ip-address/report"
		self.hashurl="https://www.virustotal.com/vtapi/v2/file/report"
		self.url="https://www.virustotal.com/vtapi/v2/url/report"
		self.scanurl="https://www.virustotal.com/vtapi/v2/url/scan"
		self.uploadfile="https://www.virustotal.com/vtapi/v2/file/scan"

	def DomainReport(self,domain):
		parameters = {'domain': domain, 'apikey': self.apikey}
		response = requests.get(self.domainurl, params=parameters)
		response_dict = response.json()
		return response_dict

	def IPReport(self,IP):
		parameters = {'ip': IP, 'apikey': self.apikey}
		response = requests.get(self.ipurl, params=parameters)
		response_dict = response.json()
		return response_dict

	def HashReport(self,md5_sha_hash):
		parameters = {'resource': md5_sha_hash, 'apikey': self.apikey}
		response = requests.get(self.hashurl, params=parameters)
		response_dict = response.json()
		return response_dict

	def UrlReport(self,url):
		parameters = {'resource': url, 'apikey': self.apikey}
		response = requests.get(self.url, params=parameters)
		response_dict = response.json()
		return response_dict

	def ScanReport(self,scanurl):
		parameters = {'url': scanurl, 'apikey': self.apikey}
		response = requests.post(self.scanurl, params=parameters)
		response_dict = response.json()
		return response_dict

	def UploadFile(self,file):
		try:
			f = open(file, 'rb')
		except IOError as e:
			print Fore.RED+"Unable to open file (File does not exist or no read permissions)"+Style.RESET_ALL
			sys.exit(-1)
		parameters = {'apikey': self.apikey}
		data = requests.post(self.uploadfile, data=parameters, files={'file':f})
		response_dict = data.json()
		return response_dict
		
parser = argparse.ArgumentParser(prog="Public API v2 VirusTotal",description='VirusTotal Search (Public API v2).')

parser.add_argument("--domain",help="Get report by a domain.")
parser.add_argument("--ip", help="Get report by an ip address.")
parser.add_argument("--hash", help="Get report by a hash.")
parser.add_argument("--url", help="Get report by a URL.")
parser.add_argument("--scanurl", help="Scan a URL.")
parser.add_argument("--uploadfile", help="Upload a file to Virus Total.")
parser.add_argument("--version", action="version", version="%(prog)s 1.0")

args = parser.parse_args()

colorama.init()

vt=PublicV2VirusTotal()

if args.uploadfile:
	uploadfile=vt.UploadFile(args.uploadfile)
	if uploadfile['response_code']==0:
		print Fore.RED+"?????."+Style.RESET_ALL
		sys.exit(-1)

	print Fore.RED+"-= Upload File Information =-"+Style.RESET_ALL
	print Fore.BLUE+'\tMessage:'+Style.RESET_ALL,uploadfile['verbose_msg']
	print Fore.BLUE+'\tLink:'+Style.RESET_ALL,uploadfile['permalink']
	print Fore.BLUE+'\tScan ID:'+Style.RESET_ALL,uploadfile['scan_id']
	print Fore.BLUE+'\tSHA1:'+Style.RESET_ALL,uploadfile['sha1']
	print Fore.BLUE+'\tSHA256:'+Style.RESET_ALL,uploadfile['sha256']
	print Fore.BLUE+'\tMD5:'+Style.RESET_ALL,uploadfile['md5']

if args.domain:
	dReport=vt.DomainReport(args.domain)
	if dReport['response_code']==0:
		print Fore.RED+"Domain not found in dataset."+Style.RESET_ALL
		sys.exit(-1)

	if 'whois' in dReport:
		print Fore.RED+"-= WHOIS Lookup =-"+Style.RESET_ALL
		print dReport['whois'], "\n"

	if 'subdomains' in dReport:
		print Fore.RED+"-= Observed Subdomains =-"+Style.RESET_ALL
		for domain in dReport['subdomains']:
			print "\t",domain
		print "\n"

	if 'resolutions' in dReport:
		print Fore.RED+"-= Resolution =-"+Style.RESET_ALL
		for resolution in dReport['resolutions']:
			print "\t",resolution['last_resolved'], resolution['ip_address']
		print "\n"

	if 'Alexa domain info' in dReport:
		print Fore.RED+"-= Alexa Ranking Information =-"+Style.RESET_ALL
		print "\t",dReport['Alexa domain info']
		print "\n"

	if 'BitDefender domain info' in dReport:
		print Fore.RED+"-= BitDefender domain Information =-"+Style.RESET_ALL
		print "\t",dReport['BitDefender domain info']
		print "\n"	

	if 'BitDefender category' in dReport:
		print Fore.RED+"-= BitDefender Category =-"+Style.RESET_ALL
		print "\t",dReport['BitDefender category']
		print "\n"

	if 'TrendMicro category' in dReport:
		print Fore.RED+"-= TrendMicro Category =-"+Style.RESET_ALL
		print "\t",dReport['TrendMicro category']
		print "\n"

	if 'Webutation domain info' in dReport:
		print Fore.RED+"-= Webtutation Domain Information =-"+Style.RESET_ALL
		print "\t","Safety Score:",dReport['Webutation domain info']['Safety score'],"Adult Content:",dReport['Webutation domain info']['Adult content'],"Verdict:",dReport['Webutation domain info']['Verdict']
		print "\n"

	if 'WOT domain info' in dReport:
		print Fore.RED+"-= WOT Domain Information =-"+Style.RESET_ALL
		print "\t","Vendor reliability:",dReport['WOT domain info']['Vendor reliability'],"Child safety:",dReport['WOT domain info']['Child safety'],"Trustworthiness:",dReport['WOT domain info']['Trustworthiness'],"Privacy:",dReport['WOT domain info']['Privacy']
		print "\n"

	if 'detected_communicating_samples' in dReport:
		print Fore.RED+"-= Latest detected files that communicate with this domain =-"+Style.RESET_ALL
		for x in dReport['detected_communicating_samples']:
			print "\t",x['date'], x['positives'],"/",x['total'],x['sha256']
		print "\n"
	
	if 'detected_urls' in dReport:
		print Fore.RED+"-= Latest detected URLs =-"+Style.RESET_ALL
		for durls in dReport['detected_urls']:
			print "\t",durls['url'], durls['positives'],"/",durls['total'],durls['scan_date']			
		print "\n"
	
	if 'detected_referrer_samples' in dReport:
		print Fore.RED+"-= Latest detected files that embed this domain in their strings =-"+Style.RESET_ALL
		for samples in dReport['detected_referrer_samples']:
			print "\t",samples['positives'],"/",samples['total'],samples['sha256']		
		print "\n"

	if 'detected_downloaded_samples' in dReport:
		print Fore.RED+"-= Latest detected files that were downloaded from this domain =-"+Style.RESET_ALL
		for latest in dReport['detected_downloaded_samples']:
			print "\t",latest['date'],latest['positives'],"/",latest['total'],latest['sha256']

if args.ip:
	ipres=re.findall(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", args.ip)
	if ipres:
		ipReport=vt.IPReport(args.ip)
		if ipReport['response_code']==0:
			print Fore.RED+"IP address not found in dataset."+Style.RESET_ALL
			sys.exit(-1)
	
		if 'country' in ipReport:
			print Fore.RED+"-= Geolocation =-"+Style.RESET_ALL
			print "\t","Country:", ipReport['country'],"Autonomous System:",ipReport['asn'],"Owner:",ipReport['as_owner']
			print "\n"

		if 'resolutions' in ipReport:
			print Fore.RED+"-= Resolution-Passive DNS Replication =-"+Style.RESET_ALL
			for resolution in ipReport['resolutions']:
				print "\t",resolution['last_resolved'], resolution['hostname']
			print "\n"

		if 'detected_communicating_samples' in ipReport:
			print Fore.RED+"-= Latest detected files that communicate with this domain =-"+Style.RESET_ALL
			for x in ipReport['detected_communicating_samples']:
				print "\t",x['date'], x['positives'],'/',x['total'],x['sha256']
			print "\n"

		if 'detected_urls' in ipReport:
			print Fore.RED+"-= Latest detected URLs =-"+Style.RESET_ALL
			for detection in ipReport['detected_urls']:
				print "\t","URL:",detection['url'], "Detection ratio:",detection['positives'],'/',detection['total'],"Scanned Date:",detection['scan_date']
			print "\n"

		if 'detected_referrer_samples' in ipReport:
			print Fore.RED+"-= Latest detected files that embed this domain in their strings =-"+Style.RESET_ALL
			for samples in ipReport['detected_referrer_samples']:
				print "\t",samples['positives'],'/',samples['total'],samples['sha256']		
			print "\n"

		if 'detected_downloaded_samples' in ipReport:
			print Fore.RED+"-= Latest detected files that were downloaded from this domain =-"+Style.RESET_ALL
			for latest in ipReport['detected_downloaded_samples']:
				print "\t",latest['date'],latest['positives'],"/",latest['total'],latest['sha256']
			print "\n"

	else:
		print Fore.RED+"Invalid IP"+Style.RESET_ALL
		sys.exit(-1)
	
if args.hash:
	result=re.findall("^[a-f\d]{32}$|^[A-F\d]{32}$|^[a-f\d]{64}$|^[A-F\d]{64}$", args.hash)
	if result:
		report=vt.HashReport(args.hash)
		if report['response_code']==0:
			print Fore.RED+"Hash not found in dataset."+Style.RESET_ALL
			sys.exit(-1)

		print Fore.RED+"-= Information =-"+Style.RESET_ALL
		print Fore.BLUE+"\tLink:"+Style.RESET_ALL,report['permalink']
		print Fore.BLUE+"\tScanID:"+Style.RESET_ALL,report['scan_id']
		print Fore.BLUE+"\tSHA1:"+Style.RESET_ALL,report['sha1']
		print Fore.BLUE+"\tSHA256:"+Style.RESET_ALL,report['sha256']
		print Fore.BLUE+"\tMD5:"+Style.RESET_ALL,report['md5']

		print "\n"

		print Fore.RED+"-= Scanned Date =-"+Style.RESET_ALL
		print "\t",report['scan_date']
		print "\n"
		print Fore.RED+"-= Detected Ratio =-"+Style.RESET_ALL
		print "\t",report['positives'],'/',report['total']
		print "\n"
		print Fore.RED+"-= Virus Total Analysis =-"+Style.RESET_ALL
		for x in report['scans']:
			print "\t", x,"\t" if len(x) < 7 else '',"\t" if len(x) < 14 else '',"\t",report['scans'][x]['detected'], "\t",report['scans'][x]['result']
	else:
		print Fore.RED+"Not a valid MD5/SHA256 hash."+Style.RESET_ALL
		sys.exit(-1)

if args.url:
	urlreport=vt.UrlReport(args.url)
	if urlreport['response_code']==0:
		print Fore.RED+"URL not found in dataset"+Style.RESET_ALL
		sys.exit(-1)

	print Fore.RED+"-= Detected Ratio =-"+Style.RESET_ALL
	print "\t",urlreport['positives'],'/',urlreport['total']
	print "\n"

	print Fore.RED+"-= Analysis Date =-"+Style.RESET_ALL
	print "\tScanned on:",urlreport['scan_date']
	print "\n"

	print Fore.RED+"-= Virus Total Analysis =-"+Style.RESET_ALL
	for x in urlreport['scans']:
		print "\t", x,"\t" if len(x) < 7 else '',"\t" if len(x) < 14 else '','\t',urlreport['scans'][x]['detected'], "\t",urlreport['scans'][x]['result']

if args.scanurl:
	scanurl=vt.ScanReport(args.scanurl)

	if scanurl['response_code']==-1:
		print Fore.RED+"Invalid URL, the scan request was not queued."+Style.RESET_ALL
		sys.exit(-1)

	print Fore.RED+"-= Link =-"+Style.RESET_ALL
	print "\t", scanurl['permalink']
	print "\n"
	print Fore.RED+"-= Scan Date =-"+Style.RESET_ALL
	print "\t", scanurl['scan_date']
	print "\n"
	print Fore.RED+"-= Scan ID =-"+Style.RESET_ALL
	print "\t", scanurl['scan_id']
	print "\n"
	print Fore.RED+"-= Message =-"+Style.RESET_ALL
	print "\t", scanurl['verbose_msg']
