from mmpy_bot import bot,settings
from mmpy_bot.bot import respond_to
from mmpy_bot.bot import listen_to
import requests
import configparser
import re
import sys
import time
import json

configfilepath = 'config.txt'
config = configparser.ConfigParser()
config.read(configfilepath)

global proxy,api_key,request
request = requests.Session()
proxies = config.get('proxy_address', 'proxy').strip("'")
api_key = config.get('virustotal', 'API_KEY').strip("'")

class re_it:
	
	def ___init__(self, name):
		self.name = name

	def regex_a_url(self,url):
		url_match = re.match('((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.[a-zA-Z0-9\.\&\/\?\:@\-_=#]*', url)
		return url_match

	def regex_md5_hash(self,file_hash):
		md5_match = re.match('^[a-f0-9]{32}$', file_hash)
		return md5_match
	
	def regex_sha1_hash(self,file_hash):
		sha1_match = re.match('^[a-f0-9]{40}$', file_hash)
		return sha1_match

	def regex_sha256_hash(self,file_hash):
		sha256_match = re.match('^[a-f0-9]{64}$', file_hash)
		return sha256_match

	def regex_an_ip(self,ip):
		ip_match = re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ip)
		return ip_match

class run_it:

	def ___init__(self, name):
		self.name = name

	def is_url_found(self,url):
		parameters = {'apikey': api_key, 'resource': url, 'allinfo': 'true'}
		uri = 'https://www.virustotal.com/vtapi/v2/url/report'
		if proxies != None or '':
			proxy = { 'http': '{}'.format(proxies),
					  'https': '{}'.format(proxies)}
			query = request.get(uri, params=parameters, proxies=proxy, timeout=5, verify=False)
			dump = query.json()

			vt_is_url_found = dump['verbose_msg']
		else:
			query = request.get(uri, params=parameters, timeout=5, verify=False)
			dump = query.json()

			vt_is_url_found = dump['verbose_msg']			
		

		if 'Domain not found' in vt_is_url_found:
			no_domain_info = True
			return no_domain_info
		else:
			no_domain_info = False
			return no_domain_info

	def is_ip_found(self,ip):
		parameters = {'apikey': api_key, 'ip': ip, 'allinfo': 'true'}
		uri = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
		if proxies != None or '':
			proxy = { 'http': '{}'.format(proxies),
					  'https': '{}'.format(proxies)}
			query = request.get(uri, params=parameters, proxies=proxy, timeout=5, verify=False)
			dump = query.json()

			vt_is_ip_found = dump['verbose_msg']
		else:
			query = request.get(uri, params=parameters, timeout=5, verify=False)
			dump = query.json()

			vt_is_ip_found = dump['verbose_msg']

		if 'IP address not found' in vt_is_ip_found:
			no_ip_info = True
			return no_ip_info
		else:
			no_ip_info = False
			return no_ip_info

	def is_hash_found(self,file_hash):
		parameters = {'apikey': api_key, 'resource': file_hash, 'allinfo': 'true'}
		uri = 'https://www.virustotal.com/vtapi/v2/file/report'
		if proxies != None or '':
			proxy = { 'http': '{}'.format(proxies),
					  'https': '{}'.format(proxies)}
			query = request.get(uri, params=parameters, proxies=proxy, timeout=5, verify=False)
			dump = query.json()

			vt_is_hash_found = dump['verbose_msg']
		else:
			query = request.get(uri, params=parameters, timeout=5, verify=False)
			dump = query.json()

			vt_is_hash_found = dump['verbose_msg']

		if 'The requested resource is not among the finished, queued or pending scans' in vt_is_hash_found:
			no_vt_hash_info = True
			return no_vt_hash_info
		else:
			no_vt_hash_info = False
			return no_vt_hash_info

	def query_a_hash(self,file_hash):
		parameters = {'apikey': api_key, 'resource': file_hash, 'allinfo': 'true'}
		uri = 'https://www.virustotal.com/vtapi/v2/file/report'
		if proxies != None or '':
			proxy = { 'http': '{}'.format(proxies),
					  'https': '{}'.format(proxies)}
			query = request.get(uri, params=parameters, proxies=proxy, timeout=5, verify=False)
			dump = query.json()

		else:
			query = request.get(uri, params=parameters, timeout=5, verify=False)
			dump = query.json()

		permalink = dump['permalink']
		positives = dump['positives']
		total = dump['total']

		try:
			malicious_votes = dump['malicious_votes']
		except:
			malicious_votes = 'No malicious votes info found.'

		try:
			community_rep = dump['community_reputation']
		except:
			community_rep = 'No community reputation info found.'
		
		try:
			harmless_votes = dump['harmless_votes']
		except:
			harmless_votes = 'No harmless votes found.'
		
		try:
			names_of_files = '\n'.join(dump['submission_names'])
		except:
			names_of_files = 'No file names found.'

		try:
			mbytes = dump['additional_info']['magic']
		except:
			mbytes = 'No Magic Bytes info found..'
		
		try:
			file_type = dump['type']
		except:
			file_type = 'No File Types found.'

		try:
			code_signing = dump['additional_info']['sigcheck']['signers details']
			signed_bin_list = []
			for signing in code_signing:
				for k,v in signing.items():
					signed_bin = '{}'.format(k) + ': ' + '{}'.format(v)
					signed_bin_list.append(signed_bin)
				signed_bin = '\n'.join(signed_bin_list)
		except:
			signed_bin = 'No Signature Data found for this hash.'

		try:
			exif_tool = dump['additional_info']['exiftool']
			exif_list = []
			for k,v in exif_tool.items():
				exif = '{}'.format(k) + ': ' + '{}'.format(v)
				exif_list.append(exif)
			exif = '\n'.join(exif_list)
		except:
			exif = 'No Exif Data found for this hash.'

		try:
			tags = dump['tags']
			tags = '\n'.join(tags)
		except:
			tags = 'No tags found for this hash.'
		
		dom_list = []
		try:
			embedded_domain = dump['additional_info']['embedded_domains']
		except:
			embedded_domain = None
		if embedded_domain is not None:
			for domain in embedded_domain:
				domain = '    ' + domain
				dom_list.append(domain)
			embedded_domains = '\n'.join(dom_list)
		else:
			embedded_domains = 'No domains found, this is found in the paid API.'

		uri_list = []
		try:
			embedded_url = dump['additional_info']['embedded_urls']
		except:
			embedded_url = None
		if embedded_url is not None:
			for url in embedded_url:
				url = '    ' + url
				uri_list.append(url)
			embedded_urls = '\n'.join(uri_list)
		else:
			embedded_urls = 'No urls found, this is found in the paid API.'

		return permalink,positives,total,malicious_votes,community_rep,names_of_files,mbytes,harmless_votes,embedded_domains,embedded_urls,signed_bin,exif,tags

	def query_url(self,url):
		parameters = {'apikey': api_key, 'resource': url, 'allinfo': 'true'}
		uri = 'https://www.virustotal.com/vtapi/v2/url/report'
		if proxies != None or '':
			proxy = { 'http': '{}'.format(proxies),
					  'https': '{}'.format(proxies)}
			query = request.get(uri, params=parameters, proxies=proxy, timeout=5, verify=False)
			dump = query.json()
		else:
			query = request.get(uri, params=parameters, timeout=5, verify=False)
			dump = query.json()


		try:
			permalink = dump['permalink']
		except:
			permalink = '	' + 'No Permalink shown.'
		try:
			positives = dump['positives']
		except:
			positives = '	' + 'No Positives value found in the api, this is possibly an error.'
		try:
			total = dump['total']
		except:
			total = '	' + 'No Total value found in the api, this is possibly an error.'
		try:
			url = dump['url']	
			url = url.replace('http', 'hxxp')
		except:
			url = '    ' + 'No URL value found in the api, this is possibly an error.'

		phish = 0
		clean = 0
		unrated = 0
		malicious = 0
		suspicious = 0
		malware = 0

		for k,v in dump['scans'].items():
			if v['result'] == 'phishing site':
				phish = phish + 1
			if v['result'] == 'clean site':
				clean = clean + 1
			if v['result'] == 'unrated site':
				unrated = unrated + 1
			if v['result'] == 'malicious site':
				malicious = malicious + 1
			if v['result'] == 'malware site':
				malware = malware + 1
			if v['result'] == 'suspicious site':
				suspicious = suspicious + 1
		return permalink,positives,total,url,phish,clean,unrated,malicious,suspicious,malware

	def query_ip(self,ip_address):
		parameters = {'apikey': api_key, 'ip': ip_address, 'allinfo': 'true'}
		uri = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
		if proxies != None or '':
			proxy = { 'http': '{}'.format(proxies),
				  'https': '{}'.format(proxies)}
			query = request.get(uri, params=parameters, proxies=proxy, timeout=5, verify=False)
			dump = query.json()
		else:
			query = request.get(uri, params=parameters, timeout=5, verify=False)
			dump = query.json()	

		try:
			auto_srv_num = dump['asn']
		except:
			auto_srv_num = None
		
		try:
			country_code = dump['country']
		except:
			country_code = None
		try:
			owner = dump['as_owner']
		except:
			owner = None
		try:
			whois = dump['whois']
		except:
			whois = None
		
		if whois == None:
			whois = '    ' + 'No whois info Found in VT.'
		else:
			whois = '    ' + 'Whois:' + '\n' + '```' + '\n' + whois + '\n' + '```'

		det_urls = dump['resolutions']
		uri_list = []
		datetime_list = []
		for uri in det_urls:
			add_urls = uri['hostname']
			add_urls = 'URL: ' + add_urls
			uri_list.append(add_urls)
			date_scan = uri['last_resolved']
			date_scan = 'Date of Last Resolution: ' + date_scan + '\n'
			datetime_list.append(date_scan)

		url_complete = []
		for uri, date_scan in zip(uri_list, datetime_list):
			items_combined = (uri + '\n' + date_scan)
			url_complete.append(items_combined)
		urls_joined = '\n'.join(url_complete)
		if not urls_joined:
			urls_joined = '    ' + 'No Domains were found to resolve to this ip'
		#Folder seens queried
		detected_folders = dump['detected_urls']
		folder_url = []
		date_of_scan = []
		for uri in detected_folders:
			adds_url = uri['url']
			adds_url = 'URL: ' + adds_url
			folder_url.append(adds_url)
			date_scans = uri['scan_date']
			date_scans = 'Date of Scan: ' + date_scans + '\n'
			date_of_scan.append(date_scans)

		complete_folder = []
		for uri, date_scan in zip(folder_url, date_of_scan):
			items_combine = (uri + '\n' + date_scan)
			complete_folder.append(items_combine)
		folder_joined = '\n'.join(complete_folder)
		if not folder_joined:
			folder_joined = '    ' + 'No folders were found'

		#Detected Hashes Resolving to that IP
		detected_samples = dump['detected_communicating_samples']
		detected_hash = []
		detected_date = []
		totals = []
		for sample in detected_samples:
			sha256_hash = sample['sha256']
			sha256_hash = 'Hash: ' + sha256_hash
			detected_hash.append(sha256_hash)
			total = sample['total']
			positives = sample['positives']
			vt_total = 'Detection Total: {}'.format(positives) + '/' + '{}'.format(total)
			totals.append(vt_total)
			sample_date = sample['date']
			sample_date = 'Submission Date: ' + sample_date + '\n'
			detected_date.append(sample_date)

		complete_detected_hashes = []
		for hashe,total,date in zip(detected_hash, totals, detected_date):
			items_comb = (hashe + '\n' + total + '\n' + date)
			complete_detected_hashes.append(items_comb)
		detect_joined = '\n'.join(complete_detected_hashes)
		if not detect_joined:
			detect_joined = '    ' + 'No Detected Hashes'

		#UnDetected Hashes Resolving to that IP
		undetected_samples = dump['undetected_communicating_samples']
		undetected_hash = []
		undetected_date = []
		totalz = []
		for samples in undetected_samples:
			un_sha256_hash = samples['sha256']
			un_sha256_hash = 'Hash: ' + un_sha256_hash
			undetected_hash.append(un_sha256_hash)
			undet_total = samples['total']
			un_positive = samples['positives']
			un_vt_total = 'Detection Total: {}'.format(un_positive) + '/' + '{}'.format(undet_total)
			totalz.append(un_vt_total)
			un_sample_date = samples['date']
			un_sample_date = 'Submission Date: ' + un_sample_date + '\n'
			undetected_date.append(un_sample_date)

		complete_undetected_hashes = []
		for un_hash,un_total,un_date in zip(undetected_hash,totalz,undetected_date):
			un_combined = (un_hash + '\n' + un_total + '\n' + un_date)
			complete_undetected_hashes.append(un_combined)
		un_detect_joined = '\n'.join(complete_undetected_hashes)
		if not un_detect_joined:
			un_detect_joined = '	' + 'No Un-Detected Hashes'

		return auto_srv_num,country_code,whois,urls_joined,folder_joined,owner,detect_joined,un_detect_joined

class rep_it:

	global initrunit
	initrunit = run_it()
	
	def ___init__(self, name):
		self.name = name
	
	def report_hash(self,message,content):
		no_hash_info = initrunit.is_hash_found(content)
		if no_hash_info:
			message.reply('VT has no record of this hash.')
		elif no_hash_info is False:
			permalink,positives,total,malicious_votes,community_rep,names_of_files,mbytes,harmless_votes,embedded_domains,embedded_urls,signed_bin,exif,tags = initrunit.query_a_hash(content)
			hash_rep_block = ('\n' +
                        '\n' + 
                        '    ' + 'File Stats' + '\n' +
                        '```' + '\n' + 
                        'Detected By: ' + str(positives) + ' ' + 'of' + ' ' + str(total) + ' AV Engines' + '\n' + 
                        'Malicious Votes: ' + str(malicious_votes) + '\n' +
                        'Community Reputation: ' + str(community_rep) + '\n' +
                        'Harmless Votes: ' + str(harmless_votes) + '\n' + 
                        '```' + '\n'
                        '    ' + 'Submission Names:' + '\n' +
                              '```' + '\n' + 
                              '{}'.format(names_of_files) + '\n' +
                              '```' + '\n' +
                        '    ' + 'Domains:' + '\n' +
                        '```' + '\n' +
                        '{}'.format(embedded_domains) + '\n' +
                        '```' + '\n' +
                        '    ' + 'Urls:' + '\n' +
                        '```' + '\n' +
                        '{}'.format(embedded_urls) + '\n' +
                        '```' + '\n' +
                        '    ' + 'Tags:' + '\n' + 
                        '```' + '\n' +
                        '{}'.format(tags) + '\n' +
                        '```' + '\n' +
                        '    ' + 'Binary Signature:' + '\n' +
                        '```' + '\n' +
                        '{}'.format(signed_bin) + '\n' +
                        '```' + '\n' +
                        '    ' + 'Exif Information:' + '\n' +
                        '```' + '\n' +
                        '{}'.format(exif) + '\n' +
                        '```' + '\n')
			message.reply('{}'.format(hash_rep_block))
			message.reply('**Link**: {}'.format(permalink))

	def report_url(self,message,content):
		no_url_info = initrunit.is_url_found(content)
		if no_url_info:
			message.reply('VT has no record of this domain.')
		elif no_url_info is False:
			permalink,positives,total,url,phish,clean,unrated,malicious,suspicious,malware = initrunit.query_url(content)
			url_rep_block = ('\n' +
                       '\n' +
                       '    ' + 'Submited URL:' + '\n' +
                       '```' + '\n' +
                       '{}'.format(url) + '\n' +
                       '```' + '\n' +
                       '    ' + 'Malicious Detection Ratio: ' + '{}'.format(positives) + '/' +'{}'.format(total) + '\n' + 
                       '```' + '\n' + 
                       'Full Detection Results:' + '\n' +
                       '```' + '\n' +
                       '    ' + 'Phishing: {}/{}'.format(phish,total) + '\n' +
                       '    ' + 'Malware: {}/{}'.format(malware,total) + '\n' +
                       '    ' + 'Malicious: {}/{}'.format(malicious,total) + '\n' +
                       '    ' + '\n' +
                       '    ' + 'Clean: {}/{}'.format(clean,total) + '\n' +
                       '    ' + 'Unrated: {}/{}'.format(unrated,total) + '\n' 
                       '    ' + 'Suspicious: {}/{}'.format(suspicious,total) + '\n' 
                       )
			message.reply('{}'.format(url_rep_block))
			message.reply('**Link**: {}'.format(permalink))

	def report_ip(self,message,content):
		no_ip_info = initrunit.is_ip_found(content)
		if no_ip_info:
			message.reply('VT has no records of this IP')
		auto_srv_num,country_code,whois,urls_joined,folder_joined,owner,detect_joined,un_detect_joined = initrunit.query_ip(content)
		ip_rep_block = ('\n' +
                    '\n' +
                    '    ' + 'IP Information:' + '\n' +
                    '\n' +
                    '```' + '\n' +
                    'ASN: {}'.format(auto_srv_num) + '\n' +
                    'Country: {}'.format(country_code) + '\n' +
                    'Owner: {}'.format(owner) + '\n' +
                    '```' + '\n' +
                    '	' + 'Un-Detected Hashes with Communication' + '\n' +
                    '```' + '\n' +
                    '{}'.format(un_detect_joined) + '\n' +
                    '```' + '\n' +
                    '	' + 'Detected Hashes with Communication:' + '\n' +
                    '```' + '\n' +
                    '{}'.format(detect_joined) +
                    '```' + '\n' +
                    '	' + 'Folders Scanned:' + '\n' +
                    '```' + '\n' +
                    '{}'.format(folder_joined) + '\n' +
                    '```' + '\n' +
                    '    ' + 'Domain Resolutions:' + '\n' +
                    '```' + '\n' + 
                    '{}'.format(urls_joined) + '\n' + 
                    '```'  + '\n')
		message.reply('{}'.format(ip_rep_block))
		message.reply('{}'.format(whois))

global initrep,initre
initrep = rep_it()
initre = re_it()

@respond_to('!vt (.*)', re.IGNORECASE)
def VT_ALL(message,content):
	char_len = len(content)
	if char_len == 32:
		md5_re = initre.regex_md5_hash(content)
		if md5_re is not None:
			initrep.report_hash(message,content)
	elif char_len == 40:
		sha1_re = initre.regex_sha1_hash(content)
		if sha1_re is not None:
			initrep.report_hash(message,content)
	elif char_len == 64:
		sha256_re = initre.regex_sha256_hash(content)
		if sha256_re is not None:
			initrep.report_hash(message,content)
	elif initre.regex_an_ip(content) is not None:
		initrep.report_ip(message,content)
	elif initre.regex_a_url(content) is not None:
		initrep.report_url(message,content)
