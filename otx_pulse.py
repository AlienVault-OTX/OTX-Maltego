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
import IndicatorTypes
import re
from OTXv2 import OTXv2
from OTXSettings import OTXSetting

def main():

	otx_settings = OTXSetting()
	otx = OTXv2(otx_settings.API_KEY)

	command_line = " ".join(sys.argv[:])
	if 'ID:' in command_line:
		pulse_id = command_line.split('ID:')[1]
		if ' ' in pulse_id:
			pulse_id = pulse_id.split(' ')[0]
		pulse_indicators = otx.get_pulse_indicators(pulse_id)

		for ind in pulse_indicators:
			indicator = ind['indicator']
			if 'FileHash' in ind['type']:
				m.addEntity("maltego.Hash", indicator)
			if ind['type'] == 'domain' or ind['type'] == 'hostname':
				m.addEntity("maltego.Domain", indicator)
			if ind['type'] == 'IPv4':
				m.addEntity("maltego.IPv4Address", indicator)

		url = 'https://otx.alienvault.com/api/v1/pulses/' + pulse_id + '/related/'
		result = requests.get(url).content
		j = json.loads(result)

		if 'results' in j:
			for pulse in j['results']:
				pulse_author = pulse['author']['username']
				if pulse_author == 'AlienVault':
					pulse_id = pulse['id']
					pulse_title = pulse['name'] + ' ID:' + pulse_id
					m.addEntity("otx.OTXPulse", pulse_title)

	return

if __name__ == '__main__':
	m = MaltegoTransform()
	m.addUIMessage("[INFO] Enriching Pulse via OTX")
	try:
		main()
	except Exception as e:
		m.addUIMessage("[Error] " + str(e) + '\n' + traceback.format_exc())
	m.returnOutput()
	