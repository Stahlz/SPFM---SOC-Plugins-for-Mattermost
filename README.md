# SPFM - SOC-Plugins-for-Mattermost #
[![GitHub license](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/Naereen/StrapDown.js/blob/master/LICENSE)
[![GitHub forks](https://img.shields.io/github/forks/Naereen/StrapDown.js.svg?style=social&label=Fork&maxAge=2592000)](https://GitHub.com/Naereen/StrapDown.js/network/)
[![GitHub stars](https://img.shields.io/github/stars/Naereen/StrapDown.js.svg?style=social&label=Star&maxAge=2592000)](https://GitHub.com/Naereen/StrapDown.js/stargazers/)
[![GitHub watchers](https://img.shields.io/github/watchers/Naereen/StrapDown.js.svg?style=social&label=Watch&maxAge=2592000)](https://GitHub.com/Naereen/StrapDown.js/watchers/)
[![GitHub followers](https://img.shields.io/github/followers/Naereen.svg?style=social&label=Follow&maxAge=2592000)](https://github.com/Naereen?tab=followers)
[![GitHub contributors](https://img.shields.io/github/contributors/Naereen/StrapDown.js.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/contributors/)

![alt text](https://i.imgur.com/vRpg5gK.gif)

**Virustotal API has a Private and Public offering, unless you have an private API key, not everything here will be shown in the results if available for a certian hash, url, or domain.**



**Info on mmpy_bot**

[mmpy_bot - Read the Docs](https://mmpy-bot.readthedocs.io/en/latest/)



**install**

```shell
pip3 install -r requirements.txt 
```

**Place plugins, including config.py inside the plugins folder**

I would remove all other plugins from this folder if you don't need them.

```shell
site-packages/mmpy_bot
               |--plugins <------Put Contents of this Repo into the Plugins folder
                  |---- urlscan.py
                  |---- virustotal.py
                  |---- config.py
```


**Add your API keys to the config.py**

**Example**
```shell
[virustotal]
API_KEY = 'd35b7424-b13d-4f34-9589-d62670cf6a33'

[urlscan]
API_KEY = '4779bcd1-52d3-425c-8d5b-d2d63155ccdd'

[proxy_address]
proxy = '10.10.100.10:8080'
```



**Add your bots login information to the settings.py**

```shell
site-packages/mmpy_bot/settings.py
```

```shell
MATTERMOST_API_VERSION = 4
BOT_URL = 'https://your-mattermost-site-url/api/v4'
BOT_LOGIN = 'yourbotsusername'
BOT_PASSWORD = None
BOT_TOKEN = 'yourbotstoken'
BOT_TEAM = 'TeamNameToJoin
SSL_VERIFY = False
WS_ORIGIN = None
WEBHOOK_ID = None  # if not specified mmpy_bot will attempt to create one
```


**Virustotal Usage**
```shell
@yourbotname !vt c7d9f5c981c6194badfc5a9389ecb21f33058c95b01dab9732e88ea0b3426a29
@yourbotname !vt https://google.com
@yourbotname !vt https://yourmalwarec2/somefolder/exfil
```


**URLScan Usage**
```shell
@yourbotname !vt https://suspiciouslink.com/
```

### Planned Additions ###
```shell
passivetotal
ThreatConnect
```

### Potential Additions ###
```shell
dnsdumpster
proofpoint
```

### Author ###

**Contact Info**
* **Joshua Whitaker** 
* *Twitter* [@_Stahlz](https://twitter.com/_Stahlz)
* *Email* - [stahl@stahl.io](stahl@stahl.io)
* *Website* - [stahl.io](http://stahl.io)
