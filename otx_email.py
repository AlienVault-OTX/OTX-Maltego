#############################################
# OTX Maltego Plugin
# 
# Email:	otx-support@alienvault.com
#############################################
import json
import requests
import sys
from MaltegoTransform import *
import traceback
from OTXv2 import OTXv2
import IndicatorTypes
import re
from OTXSettings import OTXSetting


def getDomains(email):
	domains = []
	# Note https://otx.alienvault.com/api/v1/indicator/email/ isnt available
	result = requests.get('https://otx.alienvault.com/otxapi/indicator/email/whois/' + email).content
	j = json.loads(result)
	for dom in j:
		domains.append( dom['domain'] )
	return domains

def main():
	# Todo - Used?
	otx_settings = OTXSetting()
	otx = OTXv2(otx_settings.API_KEY)
	email = sys.argv[1]

	for domain in getDomains(email):
		m.addEntity("maltego.Domain", domain)

	return

if __name__ == '__main__':
	m = MaltegoTransform()
	m.addUIMessage("[INFO] Enriching domain via OTX")
	try:
		main()
	except Exception as e:
		m.addUIMessage("[Error] " + str(e) + '\n' + traceback.format_exc())
	m.returnOutput()
	