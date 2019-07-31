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

def getPulse(general_result): 
	found_pulse = ''
	if 'pulse_info' in general_result:
		if 'pulses' in general_result['pulse_info']:
			for pulse in general_result['pulse_info']['pulses']:
				pulse_title = pulse['name']
				pulse_id = pulse['id']
				pulse_author = pulse['author']['username']
				# We want one pulse, preferably the official one
				if found_pulse == '' or pulse_author == 'AlienVault':
					found_pulse = pulse_title + ' ID:' + pulse_id

	return found_pulse

def main():
	otx_settings = OTXSetting()
	otx = OTXv2(otx_settings.API_KEY)
	ip = sys.argv[1]

	general_result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')
	found_pulse = getPulse(general_result)
	if found_pulse != '':
		m.addEntity("otx.OTXPulse", found_pulse)

	malware_result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'malware')
	pdns_result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'passive_dns')

	added_ips = 0
	if 'passive_dns' in pdns_result:
		for pdns in pdns_result['passive_dns']:
			added_ips +=1
			# Dont add too many IPs if fast flux etc
			if added_ips < 50:
				hostname = pdns['hostname']
				m.addEntity("maltego.Domain", hostname)

	if 'data' in malware_result:
		for malware in malware_result['data']:
			hash = malware['hash']
			m.addEntity("maltego.Hash", hash)
	return

if __name__ == '__main__':
	m = MaltegoTransform()
	m.addUIMessage("[INFO] Enriching IP via OTX")
	try:
		main()
	except Exception as e:
		m.addUIMessage("[Error] " + str(e) + '\n' + traceback.format_exc())
	m.returnOutput()
	