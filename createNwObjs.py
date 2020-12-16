#!/bin/env python3
import getopt
from resources import *
from restClient import FMCRestClient
import json
import requests
from datetime import datetime
import re

fmc_server_url = None
username = None
password = None
object_count=0
object_name_prefix='NWhostObject_'
action='create'

#python3.7 createNwObjs.py -s https://IPOFFMC -u USERNAME -p PASSWORD

def usage():
    print('script -s <fmc server url> -u <username> -p <password>')

def parse_args(argv):
    global fmc_server_url
    global username
    global password
    global object_count
    global object_name_prefix
    try:
        opts, args = getopt.getopt(argv,'hu:p:s:n:f:a:', ['file='])
    except getopt.GetoptError as e:
        print(str(e))
        usage()
        sys.exit(2)
    server_provided = False
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit()
        elif opt == '-u':
            username = arg
        elif opt == '-p':
            password = arg
        elif opt == '-s':
            fmc_server_url = arg
        #elif opt == '-n':
        #    object_count = int(arg)
         #   print ("object_count:", object_count);
        #elif opt == '-f':
         #   object_name_prefix = arg
        #elif opt == '-a':
            #action=arg
            #if action != 'create' || action !='delete' :
                #print('Invalid action :' , action)
                #usage()
                #sys.exit(2)
        else:
            pass
     
                         
"""
    Increment the last index number of string , ex: obj_1 to obj_2
                                                    obj_2 to obj_3
"""
def increment_str_last_index(s):
    s=re.sub(r'\d+(?=[^\d]*$)', lambda m: str(int(m.group())+1).zfill(len(m.group())), s)
    return s

def ipRange(start_ip, end_ip):
   #print("\n Inside iprange() def ")
   start = list(map(int, start_ip.split(".")))
   end = list(map(int, end_ip.split(".")))
   temp = start
   ip_range = [] 
   ip_range.append(start_ip)
   while temp != end:
      start[3] += 1
      for i in (3, 2, 1):
         if temp[i] == 256:
            temp[i] = 0
            temp[i-1] += 1
      ip_range.append(".".join(map(str, temp))) 
   return ip_range         

def ipRangeByCount(start_ip, total_ip):
   #print("\n Inside iprange() def ")
   start = list(map(int, start_ip.split(".")))
   temp = start
   ip_range = [] 
   ip_range.append(start_ip)
   i = 0
   while i < total_ip:
      ip_range.append(".".join(map(str, temp)))
      start[3] += 1
      for j in (3, 2, 1):
         if temp[j] == 256:
            temp[j] = 0
            temp[j-1] += 1
      i += 1
   return ip_range         
        
def createNWobjects(nwObjCount, nwObjName, first_nwObjvalue, last_nwObjvalue=None):
    print("create NW oBJ")
    nwObj_dict={}
    iprange = []
    if last_nwObjvalue:
        iprange = ipRange(first_nwObjvalue, last_nwObjvalue)
    else:
        iprange = ipRangeByCount(first_nwObjvalue, nwObjCount)
    for i in range(1, nwObjCount+1):
        key=nwObjName
        ip_index=i%len(iprange)
        print("ipRange[i]", iprange[ip_index])
        value=str(iprange[ip_index])
        if rest_client:
            try:           
                rest_client.create(Host(key,value))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")

def createNWProtocolPortObject(portObjName, protocol, port, desc):
    print("create NW PortObj")
    if rest_client:
            try:           
                rest_client.create(ProtocolPortObject(portObjName, protocol, port, desc))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")

def createNWSecurityZone(szName, ifMode, desc):
    print("create NW SZObj")
    if rest_client:
            try:           
                rest_client.create(SecurityZone(szName, ifMode, desc))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")    

def createNWDeviceGroup(groupName):
    print("create NW DeviceGroup")
    if rest_client:
            try:           
                rest_client.create(DeviceGroupRecord(groupName))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")  

def createNWNATPolicy(name, description):
    print("create NW NATPolicy")
    if rest_client:
            try:           
                rest_client.create(FTDNATPolicy("FTDNatPolicy", name, description))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")        
                        

def getPolicyIdByName(policyName, policyType):
    rv = {}
    list = rest_client.list(globals()[policyType]())
    for policy in list:
        if policyName == policy.name:
            rv['id'] = policy.id
            rv['type'] = policy.type
            print (policy.id)
            return rv      

def getPolicyRecordByName(policyName, policyType):
    rv = {}
    list = rest_client.list(globals()[policyType]())
    for policy in list:
        if policyName == policy.name:
            rv['id'] = policy.id
            rv['type'] = policy.type
            rv['name'] = policy.type
            print (policy.id)
            return rv 

def getPolicyByName(policyName, policyType):
    list = rest_client.list(globals()[policyType]())
    for policy in list:
        if policyName == policy.name:
            print (policy.id)
            return policy       


def getObjectByName(objectName, objectType):
    rv = {}
    list = rest_client.list(globals()[objectType]())
    for object in list:
        if objectName == object.name:
            rv['id'] = object.id
            rv['type'] = object.type
            return rv  
            
def getInterfaceByName(interfaceName, interfaceType):
    list = rest_client.list(globals()[interfaceType]())
    for interface in list:
        if interfaceName == interface.name:
            print(interface.id)
            return interface


def createNWDevice(name, type, hostName, natID, regKey, license_caps, accessPolicy):
    print("create NW Device")
    if rest_client:
            try:           
                rest_client.create(DeviceRecord(name, type, hostName, natID, regKey, license_caps, accessPolicy))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")  

def createNWAutoNatRule(type, container, originalnetwork, sourceInterface, destinationInterface):
    print("create NW Auto Nat Rule")
    if rest_client:
            try:           
                rest_client.create(AutoNatRule(type, container, originalnetwork, sourceInterface, destinationInterface))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")    

def createNWManualNatRule(type, container, sourceInterface, destinationInterface, originalSource, originalDestinationPort, translatedDestination,  translatedDestinationPort):
    print("create NW Manual Nat Rule")
    if rest_client:
            try:           
                rest_client.create(ManualNatRule(type, container, sourceInterface, destinationInterface, originalSource, originalDestinationPort, translatedDestination,  translatedDestinationPort))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")


def createNWAccessPolicy(name, defaultAction, description):
    print("create NW AccessPolicy")
    if rest_client:
            try:           
                rest_client.create(AccessPolicy(name, defaultAction, description))

            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")   

def createNWAccessRule(name, type, container, action, sourceZones, destinationZones):
    print("create NW Access Rule")
    if rest_client:
            try:           
                rest_client.create(AccessRule(name, container, action, sourceZones, destinationZones))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n")  


def createNWNetwork(name, value):
    print("create NW Network")
    if rest_client:
            try:           
                rest_client.create(Network(name, value))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n") 

def createNWAssignment(type, policy, targets):
    print("create NW Assignment")
    if rest_client:
            try:           
                rest_client.create(PolicyAssignment(type, policy, targets))
            except Exception as e:
                if(str(e)=="name-exists"):
                    print("\nObject already Exists in FMC\n") 


# def createNWInterface(name, container, ifname, enabled):
#     print("create NW Interface")
#     if rest_client:
#             try:           
#                 rest_client.create(PhysicalInterface(name, container, ifname, enabled))
#             except Exception as e:
#                 if(str(e)=="name-exists"):
#                     print("\nObject already Exists in FMC\n")    


if __name__ == "__main__":
    parse_args(sys.argv[1:])
    print("done parsing args\n")
    
    rest_client = None 
    if fmc_server_url and username and password:
        rest_client = FMCRestClient(fmc_server_url, username, password)
    
    print("Printing the objecting count:", object_count)
    print("\n")
    license_caps = [
        "BASE",
        "MALWARE",
        "URLFilter",
        "THREAT"
    ]
    createNWDeviceGroup("AWS-Autoscale")
    createNWobjects(1,"aws-metadata-server","169.254.169.254")
    createNWProtocolPortObject("aws-health-check-port", "TCP", 8080, "AWS LB HealthCheck port")
    createNWSecurityZone("Inside-sz", "ROUTED", "AWS Inside Security Zone")
    createNWSecurityZone("Outside-sz", "ROUTED", "AWS Outside Security Zone")
    createNWAccessPolicy("AWS-ACL","BLOCK", "AWS Access Policy")
    AWSAccessPolicy = getPolicyByName("AWS-ACL", "AccessPolicy")
    SourceZone = getObjectByName("Inside-sz", "SecurityZone")
    DestinationZone = getObjectByName("Outside-sz", "SecurityZone")
    createNWAccessRule("Inside -> Outside", "AccessRule", AWSAccessPolicy, "ALLOW", SourceZone, DestinationZone)
    createNWAccessRule("Outside -> Inside", "AccessRule", AWSAccessPolicy, "ALLOW", DestinationZone, SourceZone)
    createNWNATPolicy("AWS-NAT", "AWS NAT Policy")
    NatPolicy = getPolicyByName("AWS-NAT", "FTDNATPolicy")
    createNWNetwork("Public-Subnet-A", "10.0.0.0/24")
    createNWNetwork("Public-Subnet-B", "10.0.1.0/24")
    createNWNetwork("Private-Subnet-A", "10.0.10.0/24")
    createNWNetwork("Private-Subnet-B", "10.0.20.0/24")
    createNWobjects(1,"Public-Subnet-A-GW","10.0.0.1")
    createNWobjects(1,"Public-Subnet-B-GW","10.0.1.1")
    createNWobjects(1,"Private-Subnet-A-GW","10.0.10.1")
    createNWobjects(1,"Private-Subnet-B-GW","10.0.20.1")
    createNWManualNatRule("ManualNatRule", NatPolicy, DestinationZone, SourceZone, getObjectByName("any-ipv4", "Network"), getObjectByName("aws-health-check-port", "ProtocolPortObject"), getObjectByName("aws-metadata-server", "Host"), getObjectByName("HTTP", "ProtocolPortObject"))
    createNWAssignment("PolicyAssignment", getPolicyRecordByName("AWS-ACL","AccessPolicy"), [getObjectByName("AWS-Autoscale", "DeviceGroupRecord")])
    createNWAssignment("PolicyAssignment", getPolicyRecordByName("AWS-NAT","FTDNATPolicy"), [getObjectByName("AWS-Autoscale", "DeviceGroupRecord")])


    # createNWAutoNatRule("FTDAutoNatRule", NatPolicy, getObjectByName("Private-Subnet-A", "Network"), SourceZone, DestinationZone)
    # createNWAutoNatRule("FTDAutoNatRule", NatPolicy, getObjectByName("Private-Subnet-B", "Network"), SourceZone, DestinationZone)
    #createNWDevice("Test23", "Device", "10.0.100.208", "", "cisco123", license_caps, getPolicyIdByName("AWSACL", "AccessPolicy"))
    #getInterfaceByName("GigabitEthernet0/0", "PhysicalInterface")
    #createNWInterface("PhyIntfId1", getDeviceByName("vFTD66", "DeviceRecord"), "TEST", True)
    print("script ends\n")

