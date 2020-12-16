import traceback
import sys
import copy
import inspect
import json
import inspect


"""
from - http://code.activestate.com/recipes/577781-pluralize-word-convert-singular-word-to-its-plural/
"""
ABERRANT_PLURAL_MAP = {
            'appendix': 'appendices',
            'child': 'children',
            'index': 'indices',
            'man': 'men',
            'woman': 'women',
    }

VOWELS = set('aeiou')

def pluralize(singular):
    """Return plural form of given lowercase singular word (English only). Based on
    ActiveState recipe http://code.activestate.com/recipes/413172/
    """
    if not singular:
        return ''
    plural = ABERRANT_PLURAL_MAP.get(singular)
    if plural:
        return plural
    root = singular
    try:
        if singular[-1] == 'y' and singular[-2] not in VOWELS:
            root = singular[:-1]
            suffix = 'ies'
        elif singular[-1] == 's':
            if singular[-2] in VOWELS:
                if singular[-3:] == 'ius':
                    root = singular[:-2]
                    suffix = 'i'
                else:
                    root = singular[:-1]
                    suffix = 'ses'
            else:
                suffix = 'es'
        elif singular[-2:] in ('ch', 'sh'):
            suffix = 'es'
        else:
            suffix = 's'
    except IndexError:
        suffix = 's'
    plural = root + suffix
    return plural


class ObjectJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "to_json"):
            return self.default(obj.to_json())
        elif hasattr(obj, "__dict__"):
            d = dict(
                (key, value)
                for key, value in inspect.getmembers(obj)
                if not key.startswith("__")
                and not inspect.isabstract(value)
                and not inspect.isbuiltin(value)
                and not inspect.isfunction(value)
                and not inspect.isgenerator(value)
                and not inspect.isgeneratorfunction(value)
                and not inspect.ismethod(value)
                and not inspect.ismethoddescriptor(value)
                and not inspect.isroutine(value)
                and not (hasattr(obj, "hide_in_json") and obj.hide_in_json(key))
            )
            return self.default(d)
        return obj


def json_dump(obj, pretty=True):
    indent = None
    sort_keys = False
    separators=(',', ': ')
    if pretty:
        indent = 2
        sort_keys = True
        separators = None

    return json.dumps(obj, cls=ObjectJSONEncoder, indent=indent, separators=separators, sort_keys=sort_keys)

class BaseType(): 
    def __init__(self):
        self.type = self.__class__.__name__

    def _get_resource_suffix(self):
        return pluralize(self.type).lower()

    def _get_api_base(self):
        return '/api/fmc_config/v1/domain/{DOMAIN}'

    """ dump the object in json """
    def json(self,pretty=True):
       return json_dump(self, pretty)

    """ load this object from json """
    def json_load(self, json):
        pass

    def json_ignore_attrs():
        # We use unsupported* variables to indicate the original object is not completely supported.
        return ['unsupported', 'unsupportedText']

    def aggregatted_json_ignore_attrs(self):
        list = []
        for cls in inspect.getmro(self.__class__):
            if 'json_ignore_attrs' in cls.__dict__:
                list.extend(cls.json_ignore_attrs())
        return list

    def hide_in_json(self, attr_name):
        list = self.aggregatted_json_ignore_attrs()
        #print('Attribute to hide in ' + self.type + ' ' + str(list))
        #print('Attribute ' + attr_name + [' not found.', 'found'][attr_name in list])
        return attr_name in list

class BaseTypeDevice(): 
    def __init__(self):
        self.type = self.__class__.__name__

    def _get_resource_suffix(self):
        return pluralize("devicerecord").lower()

    def _get_api_base(self):
        return '/api/fmc_config/v1/domain/{DOMAIN}'

    """ dump the object in json """
    def json(self,pretty=True):
       return json_dump(self, pretty)

    """ load this object from json """
    def json_load(self, json):
        pass

    def json_ignore_attrs():
        # We use unsupported* variables to indicate the original object is not completely supported.
        return ['unsupported', 'unsupportedText']

    def aggregatted_json_ignore_attrs(self):
        list = []
        for cls in inspect.getmro(self.__class__):
            if 'json_ignore_attrs' in cls.__dict__:
                list.extend(cls.json_ignore_attrs())
        return list

    def hide_in_json(self, attr_name):
        list = self.aggregatted_json_ignore_attrs()
        #print('Attribute to hide in ' + self.type + ' ' + str(list))
        #print('Attribute ' + attr_name + [' not found.', 'found'][attr_name in list])
        return attr_name in list

class NamedType(BaseType):
    def __init__(self, name):
        BaseType.__init__(self)
        self.name = name



class NamedTypeDevice(BaseTypeDevice):
    def __init__(self, name):
        BaseTypeDevice.__init__(self)
        self.name = name

class ReferenceType():
    def __init__(self, obj):
        self.type = obj.type
        self.id = obj.id
        self.name = obj.name
        self.refCount = obj.count()
        #print('Object ' + str(obj.__class__) + ' refs ' + str(self.refCount))
        #print('Object ' + obj.type + ' refs ' + str(self.refCount))

    def hide_in_json(self, attr_name):
        return attr_name in ['refCount']

class ObjectResource(NamedType):
    def __init__(self, name):
        NamedType.__init__(self, name)
        self.elementCounts = 1
        #print('created ' + self.type + ' count '  + str(self.elementCounts))

    def get_api_path(self):
        return self._get_api_base() + '/object/' + self._get_resource_suffix()

    def json_load(self, json):
        #print('json to load ' + str(json))
        self.id = json['id']
        self.type = json['type']
        self.name = json['name']

    def count(self):
        return self.elementCounts

    def json_ignore_attrs():
        return ['elementCounts']

class PhysicalInterface(NamedType):
    def __init__(self, name=None):
        NamedType.__init__(self, name=None)
        self.name = name
        self.type = "PhyiscalInterface"
        
        print("test")

    def json_ignore_attrs():
        return ['name']

    def get_api_path(self):
        return self.get_api_base() + '/' + '/' + self._get_resource_suffix()

class DeviceGroupResource(NamedType):
    def __init__(self, name):
        NamedType.__init__(self, name)
        self.elementCounts = 1
        #print('created ' + self.type + ' count '  + str(self.elementCounts))


    def get_api_path(self):
        #print (self._get_api_base() + '/devicegroups/' + self._get_resource_suffix())
        
        return self._get_api_base() + '/devicegroups/' + self._get_resource_suffix()

    def json_load(self, json):
        #print('json to load ' + str(json))
        self.id = json['id']
        self.name = json['name']
        self.type = json['type']


    def count(self):
        return self.elementCounts

    def json_ignore_attrs():
        return ['elementCounts']

class DeviceRecordResource(NamedTypeDevice):
    def __init__(self, name):
        NamedTypeDevice.__init__(self, name)
        self.elementCounts = 1
        #print('created ' + self.type + ' count '  + str(self.elementCounts))


    def get_api_path(self):
        #print(self._get_api_base() + '/devices/' + self._get_resource_suffix())
        return self._get_api_base() + '/devices/' + self._get_resource_suffix()

    def json_load(self, json):
        #print('json to load ' + str(json))
        self.name = json['name']
        self.type = json['type']
        self.id = json['id']

    def count(self):
        return self.elementCounts

    def json_ignore_attrs():
        return ['elementCounts']

class ObjectGroupResource(ObjectResource):
    #avgDepthByType = {} # type -> avgDepth
    maxDepthByType = {} # type -> (name, maxDepth)
    
    def __init__(self, name=None, objects=[]):
        ObjectResource.__init__(self, name)
        self.objects = copy.copy(objects)
        self.elementCounts = self._count()

    def _count(self):    
        count = 0
        for objRef in self.objects:
            #print('\tTotal items in ' + objRef.type + ' ' + objRef.name + ' is ' + str(objRef.refCount))  

            if objRef.type == self.__class__.__name__:
                count += objRef.refCount
            else:
                count += 1
        #print('Total items in ' + self.type + ' ' + self.name + ' is ' + str(count))  
        if self.type not in ObjectGroupResource.maxDepthByType:
            ObjectGroupResource.maxDepthByType[self.type] = (self.name, count)
        else:
            maxDepth = ObjectGroupResource.maxDepthByType[self.type][1]
            if maxDepth < count:
                ObjectGroupResource.maxDepthByType[self.type] = (self.name, count)
        return count

    def json_ignore_attrs():
        return ['maxDepthByType', 'elementCounts']

    """
    def json_load(self, json):
        super(ObjectResource, self).json_load(json)
        print('json ' + str(json))
        self.objects = []
        # we don;t get expanded one in list command
        for refJson in json['objects']:
            obj = ObjectResource()
            obj.type = refJson['type']
            obj.id = refJson['id']
            obj.name = refJson['name']
            objRef = ReferenceType(obj)
            self.objects.append(objRef)
        self.elementCounts = self._count()
    """


class PolicyAssignmentResource(BaseType):
    def __init__(self, name):
        BaseType.__init__(self)

    def get_api_path(self):
        return self._get_api_base() + '/assignment/' + self._get_resource_suffix()

    def json_load(self, json):
        self.id = json['id']
        self.name = json['name']
        #self.description = json['description']

class PolicyResource(NamedType):
    def __init__(self, name):
        NamedType.__init__(self, name)

    def get_api_path(self):
        return self._get_api_base() + '/policy/' + self._get_resource_suffix()

    def json_load(self, json):
        self.id = json['id']
        self.name = json['name']
        #self.description = json['description']

class PolicyResourceNAT(NamedType):
    def __init__(self, name):
        NamedType.__init__(self, name)

    def get_api_path(self):
        return self._get_api_base() + '/policy/' + self._get_resource_suffix()

    def json_load(self, json):
        self.id = json['id']
        self.name = "json['name']"
        #self.description = json['description']

class ContainedPolicyResource(PolicyResource):
    def __init__(self, name, container):
        PolicyResource.__init__(self, name)
        self.container = container

    def get_api_path(self):
        return self.container.get_api_path() + '/' + self.container.id + '/' + self._get_resource_suffix()
    
    def json_ignore_attrs():
        return ['container']

class ContainedPolicyResourceNAT(PolicyResource):
    def __init__(self, name, container, sourceInterface, destinationInterface):
        PolicyResource.__init__(self, name)
        self.container = container
        self.sourceInterface = sourceInterface
        self.destinationInterface = destinationInterface

    def get_api_path(self):
        return self.container.get_api_path() + '/' + self.container.id + '/' + self._get_resource_suffix()
    
    def json_ignore_attrs():
        return ['container']



class SecurityZone(ObjectResource):
    def __init__(self, name=None, interface_mode=None, desc=None, is_ifc_group=False):
        ObjectResource.__init__(self, name)
        self.interfaceMode = interface_mode
        self.description = desc
        self.interfaces = []

        
class Network(ObjectResource):
    def __init__(self, name=None, value=None):
        ObjectResource.__init__(self, name)
        self.value = value

class Host(ObjectResource):
    def __init__(self, name=None, value=None):
        ObjectResource.__init__(self, name)
        self.value = value


class NetworkGroup(ObjectGroupResource):
    def __init__(self, name=None, objects=[]):
        ObjectGroupResource.__init__(self, name, objects)

class Port(ObjectResource):
    def __init__(self, name=None, protocol=None, desc=None):
        ObjectResource.__init__(self, name)
        self.protocol = protocol
        self.description = desc


class DeviceGroupRecord(DeviceGroupResource):
    def __init__(self, name=None, type="DeviceGroup" , members=[]):
        DeviceGroupResource.__init__(self, name)
        self.members = members


class DeviceRecord(DeviceRecordResource):
    def __init__(self, name=None, type="Device", hostName=None, natID=None, regKey=None, license_caps=[], accessPolicy={}):
        DeviceRecordResource.__init__(self, name)
        self.name = name
        self.hostName = hostName
        self.natID = natID
        self.regKey = regKey
        self.type = "Device"
        self.license_caps = license_caps
        self.accessPolicy = accessPolicy


class PolicyAssignment(PolicyAssignmentResource):
    def __init__(self, type="PolicyAssignment", policy=None, targets=[]):
        PolicyAssignmentResource.__init__(self, type)
        self.type = "PolicyAssignment"
        self.policy = policy
        self.targets = targets

class ProtocolPortObject(Port):
    def __init__(self, name=None, protocol='tcp', port='1-65535', desc=None):
        Port.__init__(self, name, protocol, desc)
        self.port = port

class ICMPPortObject(Port):
    def __init__(self, name=None, protocol=None, type=None, code=None, desc=None):
        Port.__init__(self, name, protocol, desc)
        self.icmpType = type
        self.code = code

    def json_ignore_attrs():
        return ['protocol']

class ICMPV4Object(ICMPPortObject):
    def __init__(self, name=None, type=None, code=None, desc=None):
        ICMPPortObject.__init__(self, name, 'icmpv4', type, code, desc)

class ICMPV6Object(ICMPPortObject):
    def __init__(self, name=None, type=None, code=None, desc=None):
        ICMPPortObject.__init__(self, name, 'icmpv6', type, code, desc)

class PortObjectGroup(ObjectGroupResource):
    def __init__(self, name=None, objects=[], desc=None):
        ObjectGroupResource.__init__(self, name, objects)
        self.description = desc

class SecurityGroupTag(ObjectResource):
    def __init__(self, name=None, tag=None, desc=None):
        ObjectResource.__init__(self, name)
        self.tag = tag
        self.description = desc


"""
{
  "type": "AccessPolicy",
  "name": "AccessPolicy1",
  "description": "policy to test FMC implementation",
  "defaultAction": {
    "type": "AccessPolicyDefaultAction",
    "logBegin": "false",
    "logEnd": "false",
    "sendEventsToFMC": "false",
    "action": "3"
  }
}
"""
class AccessPolicy(PolicyResource):
    
    def __init__(self, name=None, default_action='ALLOW', desc=None):
        PolicyResource.__init__(self, name)
        self.name = name
        self.description = desc
        self.defaultAction = AccessPolicyDefaultAction(self, default_action)

class FTDNATPolicy(PolicyResource):
    
    def __init__(self, type=None, name=None, desc=None):
        PolicyResource.__init__(self, name)
        self.type = "FTDNatPolicy"
        self.name = name
        self.description = desc


class AccessPolicyDefaultAction(ContainedPolicyResource):

    def __init__(self, container=None, action='ALLOW', log_begin=False, log_end=True):
        ContainedPolicyResource.__init__(self, None, container)
        self.logBegin = log_begin
        self.logEnd = log_end
        self.sendEventsToFMC = True
        self.action = action

    def json_ignore_attrs():
        return ['name']

    
"""
{
  "action": "ALLOW",
  "enabled": true,
  "type": "AccessRule",
  "name": "Rule1",
  "sendEventsToFMC": false,
  "logFiles": false,
  "logBegin": false,
  "logEnd": false,
  "variableSet": {
    "name": "Default Set",
    "id": "VariableSetUUID",
    "type": "VariableSet"
  }
}

"""
class AccessRule(ContainedPolicyResource):
    maxFlattenedRules = None # (rule, count)
    maxRuleEnteries = None # (rule, count)

    def __init__(self, name=None, container=None, action=None, sourceZones={}, destinationZones={}):
        ContainedPolicyResource.__init__(self, name, container)
        self.name = name
        self.action = 'ALLOW' 
        self.sendEventsToFMC = True
        self.logBegin = False
        self.logEnd = True
        self.enabled = True
        self.newComments = []
        self.sourceZones = {'objects': [sourceZones] }
        self.destinationZones = { 'objects': [destinationZones] }
        self.sourceNetworks = { 'objects': [] }
        self.destinationNetworks = { 'objects': [] }
        self.sourcePorts = { 'objects':  [] }
        self.destinationPorts = { 'objects': [] }
       

    def count(self, flattenedCompltely=True):
        ruleCount = 1
        dimRefsList = [ self.sourceZones['objects'], self.destinationZones['objects'], 
                   self.sourceNetworks['objects'], self.destinationNetworks['objects'],
                   self.sourcePorts['objects'], self.destinationPorts['objects'] ]
        for dimRefs in dimRefsList:
            ruleCount = ruleCount * self.dimensionCount(dimRefs, flattenedCompltely)
        if flattenedCompltely:
            if AccessRule.maxRuleEnteries is None or AccessRule.maxRuleEnteries[1] < ruleCount:
                AccessRule.maxRuleEnteries = (self, ruleCount)
        else:
            if AccessRule.maxFlattenedRules is None or AccessRule.maxFlattenedRules[1] < ruleCount:
                AccessRule.maxFlattenedRules = (self, ruleCount)
        return ruleCount

    def dimensionCount(self, singleDimensionRefs, flattenedCompltely=True):
        dimCount = 0
        for dimRef in singleDimensionRefs:
            if flattenedCompltely:
                dimCount += dimRef.refCount
            else:
                dimCount += 1
        if dimCount == 0: #consider any
            dimCount = 1
        return dimCount

    def json_ignore_attrs():
        return ['maxFlattenedRules', 'maxRuleEnteries']


class AccessRulesBulk(ContainedPolicyResource):

    def __init__(self, data, container=None):
        ContainedPolicyResource.__init__(self, None, container)
        self.data = data
        
    def json_ignore_attrs():
        return ['name', 'description', 'type', 'id']

    def _get_resource_suffix(self):
        return (self.type).lower()

    def json_load(self, json):
        pass





class AutoNatRule(ContainedPolicyResourceNAT):


    def __init__(self, type=None, container=None, originalNetwork=None, sourceInterface=None, destinationInterface=None):
        ContainedPolicyResourceNAT.__init__(self, type, container, sourceInterface=None, destinationInterface=None)
        self.originalNetwork = originalNetwork
        self.type = "AutoNatRule"
        self.natType = "DYNAMIC"
        self.interfaceIpv6 = False
        self.fallThrough = False
        self.dns = False
        self.routeLookup = False
        self.noProxyArp = False
        self.netToNet = False
        self.sourceInterface = sourceInterface
        self.destinationInterface = destinationInterface
        self.interfaceInTranslatedNetwork = True

    def json_ignore_attrs():
        return ['name']

class ManualNatRule(ContainedPolicyResourceNAT):


    def __init__(self, type=None, container=None, sourceInterface=None, destinationInterface=None, originalSource=None, originalDestinationPort=None, translatedDestination=None,  translatedDestinationPort=None):
        ContainedPolicyResourceNAT.__init__(self, type, container, sourceInterface=None, destinationInterface=None)
        self.type = "ManualNatRule"
        self.natType = "STATIC"
        self.enabled = True
        self.interfaceIpv6 = False
        self.fallThrough = False
        self.dns = False
        self.routeLookup = False
        self.noProxyArp = False
        self.netToNet = False
        self.interfaceInTranslatedSource = True
        self.interfaceInOriginalDestination = True
        self.sourceInterface = sourceInterface
        self.destinationInterface = destinationInterface
        self.originalSource = originalSource
        self.originalDestinationPort = originalDestinationPort
        self.translatedDestination = translatedDestination
        self.translatedDestinationPort = translatedDestinationPort
        

    def json_ignore_attrs():
        return ['name']


### Used only for the converter purpose, not FMC object ###    
""" holds source and destination port object or group """
class ServiceContainer():
    
    def __init__(self, name, sources=[], destinations=[], isGroup=False):
        self.name = name
        self.type = "ServiceContainer"
        
        ## IMP: Creating local copy of the list, otherwise strangely these lists were 
        ## getting shared with all ServiceContainer instances
        self.sources = copy.copy(sources)
        self.destinations = copy.copy(destinations)

        self.isGroup = isGroup
    
    def __str__(self):
        return 'Service container - ' + self.name + '\n' + \
            '\tself.sources id ' + str(id(self.sources)) + ' length ' + str(len(self.sources)) + \
            '\tself.destinations' + str(id(self.destinations)) + ' length ' + str(len(self.sources))

