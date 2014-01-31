#!/usr/bin/python

# https://pypi.python.org/pypi/netifaces
# http://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib


#from netifaces import interfaces, ifaddresses, AF_INET
import netifaces

ipv4_config = {}
for ifaceName in netifaces.interfaces():
     ipv4_config[ifaceName] = [i['addr'] for i in netifaces.ifaddresses(ifaceName).setdefault(netifaces.AF_INET, [] )]

print ipv4_config
print [ ipv4_config[dev] for dev in ipv4_config.keys() ]
print [addr for dev in ipv4_config.keys() for addr in  ipv4_config[dev] ]


