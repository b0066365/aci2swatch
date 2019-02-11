#!/usr/bin/env python
# -*- coding: UTF-8 -*-# enable debugging

print """
--------------------
Copyright (c) 2019 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
---------------------
"""

__author__ = "Dirk Woellhaf <dwoellha@cisco.com>"
__contributors__ = [
    "Dirk Woellhaf <dwoellha@cisco.com>"
]
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.0"

import requests
import json
import sys
import os
import time
import ConfigParser
import getpass
import base64
import logging

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def APIC_Login(apic, logging):
    #print "APIC Login..."

    # create credentials structure
    apic_data = '{"aaaUser":{"attributes":{"name":"","pwd":""}}}'
    apic_data=json.loads(apic_data)
    apic_data["aaaUser"]["attributes"]["name"] = apic["USER"]
    apic_data["aaaUser"]["attributes"]["pwd"] = apic["PASSWORD"]

    # log in to API
    post_response = requests.post("https://"+str(apic["IP"])+"/api/aaaLogin.json", data=json.dumps(apic_data), verify=False)
    if post_response.status_code == 200:
      # get token from login response structure
      auth = json.loads(post_response.text)
      login_attributes = auth['imdata'][0]['aaaLogin']['attributes']
      auth_token = login_attributes['token']
      Logger(logging, "debug", "APIC Login success. Token: "+auth_token)
      return auth_token
    else:
      print "ERR: "+ post_response.text
      Logger(logging, "error", "APIC Login failed. Exiting... "+post_response.text)
      sys.exit()

def APIC_Get(get_url,apic_ip,cookies, logging):
    get_response = requests.get("https://"+str(apic_ip)+"/api"+str(get_url), cookies=cookies,verify=False)
    get_error = json.loads(get_response.text)

    # Catching Error-Message when something went wrong:
    if get_error['totalCount'] <= "0":
        print "ERR: "+ json.dumps(get_response.text)
        Logger(logging, "error", "APIC "+get_response.text)
    else:
        #print "OK"
        Logger(logging, "debug", "APIC GET succesful. "+get_response.text)
        return get_error

def GetGlobalEndpoints(apic, logging):
    cookies = {}
    ACIEndPoints = []
    ACIEPGs = []
    cookies['APIC-Cookie'] = APIC_Login(apic, logging)

    get_data = APIC_Get('/node/class/fvCEp.json',APIC["IP"],cookies, logging)

    C=1
    while C <= int(get_data["totalCount"]):
      if get_data["imdata"][C-1]["fvCEp"]["attributes"]["ip"] != "0.0.0.0" and "epg-" in get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"]:
          ACIEndPoints.append(get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"].upper() + "/"+ get_data["imdata"][C-1]["fvCEp"]["attributes"]["ip"])
          if get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"].upper() not in ACIEPGs:
            ACIEPGs.append(get_data["imdata"][C-1]["fvCEp"]["attributes"]["dn"].upper())
      C+=1

    #print "Total ACI EndPoints: " + get_data["totalCount"]
    Logger(logging, "info", "APIC EndPoints. "+get_data["totalCount"])

    return ACIEndPoints, ACIEPGs

def ACI2Config(aci_endpoints, config, logging):
  aci_groups = []

  Logger(logging, "debug", "APIC EndPoints: "+str(aci_endpoints))

  for aci_endpoint in aci_endpoints:
    aci_endpoint = aci_endpoint.split("/")
    aci_tenant = aci_endpoint[1] #.lstrip("TN-")
    aci_ap = aci_endpoint[2] #.lstrip("AP-")
    aci_epg = aci_endpoint[3] #.lstrip("EPG-")

    #print aci_groups
    NewSection = aci_tenant+"_"+aci_ap+"_"+aci_epg

    #print len(NewSection)
    if len(SWATCH["PREFIX"])+len(NewSection) > 64:
      MaxLength = 64 - len(SWATCH["PREFIX"])
      NewSection=NewSection[:MaxLength]
      #print NewSection

    if NewSection not in aci_groups:
      Logger(logging, "debug", "APIC Creating new Config-Section: "+NewSection)
      config.add_section(NewSection)
      aci_groups.append(NewSection)

    aci_ep = aci_endpoint[5]
    config.set(NewSection, aci_ep)

  #time.sleep(0.5)
  return config

def SWATCH_Login(swatch_ip, swatch_user, swatch_password, logging):
    #print "SWATCH Login..."

    # create credentials structure
    payload = {'username': swatch_user, 'password': swatch_password}
    headers = {'Content-Type': "application/x-www-form-urlencoded",'cache-control': "no-cache"}

    # log in to API
    post_response = requests.post("https://"+str(swatch_ip)+"/token/v2/authenticate", data=payload, headers=headers, verify=False)
    
    if post_response.status_code == 200:
      #print post_response.cookies['stealthwatch.jwt']
      Logger(logging, "debug", "SWATCH Login success. Token: "+post_response.cookies['stealthwatch.jwt'])
      #return post_response.cookies['stealthwatch.jwt']
      return post_response.cookies
    else:
      print "ERR: "+ post_response.text
      Logger(logging, "error", "SWATCH Login failed. Exiting... "+post_response.text)
      sys.exit()

def SWATCH_Get(get_url, swatch, logging):
    get_response = requests.get("https://"+str(swatch["IP"])+str(get_url), cookies=swatch["COOKIE"],verify=False)
    get_error = json.loads(get_response.text)

    # Catching Error-Message when something went wrong:
    if len(get_error['data']) < 1:
        print "ERR: "+ json.dumps(get_response.text)
        Logger(logging, "error", "SWATCH "+get_response.text)
    else:
        #print "OK"
        Logger(logging, "debug", "SWATCH GET succesful. "+get_response.text)
        return get_error

def SWATCH_Post(get_url, payload, swatch, logging):
    headers = {'Content-Type': "application/json"}
    post_response = requests.post("https://"+str(swatch["IP"])+str(get_url), headers=headers, json=payload, cookies=swatch["COOKIE"],verify=False)
    post_error = json.loads(post_response.text)

    return post_error

def SWATCH_Put(url, payload, swatch, logging):
    headers = {'Content-Type': "application/json"}
    post_response = requests.put("https://"+str(swatch["IP"])+str(url), headers=headers, json=payload, cookies=swatch["COOKIE"],verify=False)
    post_error = json.loads(post_response.text)

    return post_error

def CheckExistingGroups(HostGroup, swatch,logging):
  result = SWATCH_Get("/smc-configuration/rest/v1/tenants/"+str(swatch["DomainID"])+"/tags", swatch, logging)
  # Check for existing group and return Group ID if found
  for ExistingHostGroup in result["data"]:
    if ExistingHostGroup["name"] == HostGroup:
      return ExistingHostGroup["id"]

def Epg2Swatch(epg_list, swatch, apic, logging):
  # Get Tenant ID
  result = SWATCH_Get("/sw-reporting/v1/tenants", swatch, logging)
  swatch["DomainID"] = result["data"][0]["id"]
  #result = CheckExistingGroups(swatch,logging)

  # Get Existing HostGroups to find Parent HostGroup ID
  result = SWATCH_Get("/smc-configuration/rest/v1/tenants/"+str(swatch["DomainID"])+"/tags", swatch, logging)

  for ExistingHostGroup in result["data"]:
    if ExistingHostGroup["name"] == swatch["PARENTGROUP"]:
      swatch["PARENTGROUPID"] = ExistingHostGroup["id"]

  # Build Payload to create APIC Parent Group
  payload = [{
    "name": "APIC_"+apic["IP"].upper(),
    "location": "INSIDE",
    "description": "Host Groups from APIC: "+apic["IP"].upper(),
    "hostBaselines": swatch["HOSTBASELINES"],
    "suppressExcludedServices": True,
    "inverseSuppression": False,
    "hostTrap": False,
    "sendToCta": False,
    "parentId": swatch["PARENTGROUPID"]
  }]

  # Create APIC Parent Group
  result = SWATCH_Post("/smc-configuration/rest/v1/tenants/"+str(swatch["DomainID"])+"/tags", payload, swatch, logging)

  # If failed, check if group already exists
  if "errors" in result:
    swatch["APICHostGroupID"] = CheckExistingGroups("APIC_"+apic["IP"].upper(), swatch, logging)
  else:
    swatch["APICHostGroupID"]= result["data"][0]["id"]

  #print swatch["APICHostGroupID"]

    

  for NewSection in epg_list.sections():
    # Build Payload to create APIC Parent Group
    payload = [{
      "name": "",
      "location": "INSIDE",
      "description": "Host Group from APIC: "+apic["IP"].upper(),
      "ranges": [],
      "hostBaselines": swatch["HOSTBASELINES"],
      "suppressExcludedServices": True,
      "inverseSuppression": False,
      "hostTrap": False,
      "sendToCta": False,
      "parentId": swatch["APICHostGroupID"]
    }] 

    payload[0]["name"] = NewSection
    
    for EndPoint in epg_list.items(NewSection):
      payload[0]["ranges"].append(EndPoint[0])

    #print payload  
    result = SWATCH_Post("/smc-configuration/rest/v1/tenants/"+str(swatch["DomainID"])+"/tags", payload, swatch, logging)
    if "errors" in result:
      ExistingID=0
      ExistingID = CheckExistingGroups(NewSection, swatch, logging)
      if ExistingID !=0:
        payload[0]["id"]= ExistingID
        result = SWATCH_Put("/smc-configuration/rest/v1/tenants/"+str(swatch["DomainID"])+"/tags", payload, swatch, logging)

    payload = ""

def Logger(logging, level, msg):
  if level == "debug":
    logging.debug(msg)
  elif level == "info":
    logging.info(msg)
  elif level == "warning":
    logging.warning(msg)
  elif level == "error":
    logging.error(msg)
  elif level == "critical":
    logging.critical(msg)

if __name__ == "__main__":
  print "Starting..."
  i = 0
  while i == 0 :
    LOG_LEVEL="debug"
    SWATCH={}
    APIC={}
    GLOBAL={}

    config = ConfigParser.SafeConfigParser(allow_no_value=True)
    config.read('/home/app/src/config.cfg')
    GLOBAL["UPDATE_INTERVAL"] = config.get('GLOBAL', 'UPDATE_INTERVAL')
    #GLOBAL["LOG_DIR"] = config.get('GLOBAL', 'LOG_DIR')
    GLOBAL["LOG_FILE"] = config.get('GLOBAL', 'LOG_FILE')
    GLOBAL["LOG_LEVEL"] = config.get('GLOBAL', 'LOG_LEVEL')
    APIC["IP"] = config.get('APIC', 'APIC_IP')
    APIC["USER"] = config.get('APIC', 'APIC_USER')
    APIC["PASSWORD"] = base64.b64decode(config.get('APIC', 'APIC_PASSWORD'))

    SWATCH["IP"] = config.get('SWATCH', 'SWATCH_IP')
    SWATCH["USER"] = config.get('SWATCH', 'SWATCH_USER')
    SWATCH["PASSWORD"] = base64.b64decode(config.get('SWATCH', 'SWATCH_PASSWORD'))
    SWATCH["PREFIX"] = config.get('SWATCH', 'SWATCH_PREFIX')
    SWATCH["PARENTGROUP"] = config.get('SWATCH', 'SWATCH_PARENTGROUP')
    SWATCH["HOSTBASELINES"] = config.get('SWATCH', 'SWATCH_HOSTBASELINES')


    if LOG_LEVEL == "debug":
      logging.basicConfig(filename=GLOBAL["LOG_FILE"],format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.DEBUG)
    elif LOG_LEVEL == "info":
      logging.basicConfig(filename=GLOBAL["LOG_FILE"],format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.INFO)
    else:
      logging.basicConfig(filename=GLOBAL["LOG_FILE"],format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %I:%M:%S %p', level=logging.WARNING)

    epg_config = ConfigParser.SafeConfigParser(allow_no_value=True)

    Logger(logging, "info", "Using: APIC IP: "+APIC["IP"]+", APIC User: "+APIC["USER"]+", SWATCH IP: "+SWATCH["IP"]+", SWATCH User: "+SWATCH["USER"]+", INTERVAL: "+GLOBAL["UPDATE_INTERVAL"])
    Logger(logging, "info", "Current Log-Level: "+GLOBAL["LOG_LEVEL"])

    # APIC
    aci_endpoints, aci_epgs = GetGlobalEndpoints(APIC, logging)
    epg_config =  ACI2Config(aci_endpoints, epg_config, logging)

    with open('/home/app/src/epgs.cfg', 'wb') as epg_configfile:
      epg_config.write(epg_configfile)

    # SWATCH
    epg_list = ConfigParser.SafeConfigParser(allow_no_value=True)
    epg_list.read('/home/app/src/epgs.cfg')

    SWATCH["COOKIE"] = SWATCH_Login(SWATCH["IP"],SWATCH["USER"],SWATCH["PASSWORD"],logging)
    Epg2Swatch(epg_list, SWATCH, APIC, logging)


    # Clean up
    SWATCH={}
    APIC={}
    GLOBAL={}

    # Sleep
    print "Sleeping for "+GLOBAL["UPDATE_INTERVAL"]+"s..."
    Logger(logging, "info", "Sleeping for "+GLOBAL["UPDATE_INTERVAL"]+"s...")
    time.sleep(int(GLOBAL["UPDATE_INTERVAL"]))