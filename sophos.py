#!/usr/bin/python

import sys
from xml.etree import ElementTree
import csv

# Quick & Dirty Sophos XG Rule Reviewer

# Open file to be parsed
with open(sys.argv[1], 'rt') as xmlfile:
	tree = ElementTree.parse(xmlfile)

# Open file to write to
outfile = csv.writer(open("CSVoutput.csv", "wb"))
outfile.writerow(["Rulename","Ruledescription","Rulestatus","Rulesource","Ruledestination","RuleAction","RuleLog","RuleServices"])

for rules in tree.iter('SecurityPolicy'):
	name = ""
	desc = ""
	status = ""
	action = ""
	log = ""
	finalsource =""
	finaldest = ""
	finalservice = ""
	for rule in rules.getchildren():
		if str(rule.tag) == "Name":
			name = rule.text
		if str(rule.tag) == "Description":
			desc = rule.text
		if str(rule.tag) == "Status":
			status = rule.text
		if str(rule.tag) == "Action":
			action = rule.text
		if str(rule.tag) == "LogTraffic":
			log = rule.text
		if str(rule.tag) == "SourceZones":
			sourcezones = rule.getchildren()
			sources = []
			for source in sourcezones:
				sources.append(source.text)
			finalsource = " ".join(sources)
		if str(rule.tag) == "DestinationZones":
			destzones = rule.getchildren()
			dests = []
			for dest in destzones:
				dests.append(dest.text)
			finaldest = " ".join(dests)
		if str(rule.tag) == "Services":
			services = rule.getchildren()
			servs = []
			for service in services:
				servs.append(service.text)
			finalservice = " ".join(servs)
	outfile.writerow([name,desc,status,finalsource,finaldest,action,log,finalservice])
