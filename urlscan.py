from mmpy_bot import bot,settings
from mmpy_bot.bot import respond_to
from mmpy_bot.bot import listen_to
import requests
import configparser
import re
import time
import json

configfilepath = 'config.txt'
config = configparser.ConfigParser()
config.read(configfilepath)

global proxy, api_key
proxies = config.get('proxy_address', 'proxy').strip("'")
api_key = config.get('urlscan', 'API_KEY').strip("'")


def regex_a_url(url):
    match_url = re.match('((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z0-9\.\&\/\?\:@\-_=#]*', url)
    return regex_a_url

def send_url(url):
    request = requests.Session()

    submission_header = {'API-KEY': api_key, 'Content-Type': 'application/json'}
    
    url_to_submit = {"url": url, "visibility": "private"} 
    
    if proxies == '':
        proxy = { 'http': '{}'.format(proxies),
  	          'https': '{}'.format(proxies)}
        submit_url = request.post('https://urlscan.io/api/v1/scan', proxies=proxy, headers=submission_header, data=url_to_submit, verify=False)
        submission_response = submit_url.json()
        return submission_response['uuid']
    elif proxies != '':
        submit_url = request.post('https://urlscan.io/api/v1/scan', headers=submission_header, data=json.dumps(url_to_submit), verify=False)
        submission_response = submit_url.json()
        return submission_response['uuid']

@respond_to('!urlscan (.*)', re.IGNORECASE)
def scanurl(message, content):
    print('Url Submitted: {}'.format(content))
    if regex_a_url is not None:
        message.reply('Sent {} to urlscan'.format(content))
        uuid = send_url(content)
        time.sleep(30)
        message.reply('![Mattermost](https://urlscan.io/screenshots/{}.png "UrlScan Submission")'.format(uuid))
        message.reply('Result: https://urlscan.io/result/{}'.format(uuid))
    elif regex_a_url is None:
        message.reply('This does not appear to be a url, please try agian. Please submit the urls one at a time.')
        message.reply('Example: !urlscan https://google.com')
