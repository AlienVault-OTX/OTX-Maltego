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
	hash = sys.argv[1]

	indicator_type = IndicatorTypes.FILE_HASH_SHA256
	if len(hash) == 40:
		indicator_type = IndicatorTypes.FILE_HASH_SHA1
	if len(hash) == 32:
		indicator_type == IndicatorTypes.FILE_HASH_MD5

	general_result = otx.get_indicator_details_by_section(indicator_type, hash, 'general')
	found_pulse = getPulse(general_result)
	if found_pulse != '':
		m.addEntity("otx.OTXPulse", found_pulse)

	analysis_result = otx.get_indicator_details_by_section(indicator_type, hash, 'analysis')
	try:
		domainsJ = analysis_result['analysis']['plugins']['cuckoo']['result']['network']['domains']
		for dns in domainsJ:
			# { 'ip': '', 'domain': '' }
			if len(str(dns).split("'")) > 6:
				domain = str(dns).split("'")[7]
				ip = str(dns).split("'")[3]
				m.addEntity("maltego.IPv4Address", ip)
				m.addEntity("maltego.Domain", domain)
	except Exception as ex:
		pass

	return

if __name__ == '__main__':
	m = MaltegoTransform()
	m.addUIMessage("[INFO] Enriching Hash via OTX")
	try:
		main()
	except Exception as e:
		m.addUIMessage("[Error] " + str(e) + '\n' + traceback.format_exc())
	m.returnOutput()
	