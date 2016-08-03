#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sf_cli
# Purpose:      Command line interface to Spiderfoot
#
# Author:      Koen Van Impe
#
# Created:     30/12/2015
# Copyright:   (c) Koen Van Impe
# Licence:     GPL
# -------------------------------------------------------------------------------

import requests
import time
import sys

'''
Configure where your instance of Spiderfoot is running
Adjust
 sf_host
 sf_port
 sf_usecase
'''

sf_host = "192.168.218.21"
sf_port = "5001"
sf_usecase = "Intelligence"
verbose = False

sf_scanname = sys.argv[1]
sf_scantarget = sys.argv[2]
sf_modulelist = ""
sf_typelist = ""
time_sleep = 120
internal_id_str = "Internal ID:"
internal_id_str_stop = "</td><td>"
scanid_stop_str = "</td></tr>"
sf_request = "http://" + sf_host + ":" + sf_port


payload = { 'scanname': sf_scanname, 
            'scantarget': sf_scantarget, 
            'usecase': sf_usecase, 
            'modulelist': sf_modulelist, 
            'typelist': sf_typelist}

if verbose:
    print "Posting request to %s " % sf_request
r = requests.post( sf_request + "/startscan", payload)
response = r.text

internal_id = response.find(internal_id_str) + len(internal_id_str) + len (internal_id_str_stop)
internal_id_stop = response.find(scanid_stop_str, internal_id)
scan_id = response[internal_id:internal_id_stop]

if verbose:
    print "Returned scan_id is %s " % scan_id
    print "Now waiting for %s seconds for scan data getting ready" % time_sleep
time.sleep(time_sleep)

if verbose:
    print "Requesting the scan results"
response = requests.get( sf_request + "/scaneventresultexportmulti?ids=%s" % scan_id )
print response.text

