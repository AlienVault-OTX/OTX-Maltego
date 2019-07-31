# OTX Maltego Transforms - Beta
 + A set of transforms for enriching entities in Maltego via the OTX API

== Transforms ==
 + Domains (Domain)
 + IP Addresses (IPv4 Address)
 + MD5 Hashes of malware (Hash)
 + E-mail Addresses (Email Address)
 + Antivirus detection names (Phrase)

== Installation  = =
 + Copy all files to eg; /Maltego/OTX
 + Edit the API_KEY in OTXSettings.py to your own API KEY
 + Import "OTXConfig.mtz" into Maltego via File -> Import Configuration
 + Click Transform manager, then for each OTX transform:
 + Update the "Command Line" column to your python binary location egg /bin/python3
 + Update whr "Working Directory" column to the location you saved the files to, eg; /Maltego/OTX
 
== Contact ==
 + otx-support@alienvault.com
