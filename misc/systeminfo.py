#!/usr/bin/python

import subprocess as sub
import re
import os

def run_command(cmd):
    p = sub.Popen(cmd,stdout=sub.PIPE,stderr=sub.PIPE)
#   if not p.wait():
#       raise Exception('spam', 'eggs')
    output, errors = p.communicate()

    return (output, errors)


def find_option(option, s, multiple=False):
    '''
    If multiple=False, and there are several matches then only the LAST one gets reported
    If multiple=True, an array with all matches gets returned
    '''

    result = []
    for line in s.split('\n'):
        if re.match('^[ \t]*%s.*' % option,line):
            line = re.sub('^[ \t]*%s[ \t:]*' % option, '', line)
            line = re.sub('[ \t]*$', '', line)
            if multiple:
                result.append(line)
            else:
                result = line
    return result


def disk_info(disk):
    info = {}
    command = '/sbin/hdparm -I /dev/%s' % disk
    hdparm = run_command(command.split())[0]
    info['model'] = find_option('Model Number:', hdparm)
    info['serial'] = find_option('Serial Number:', hdparm)
    info['size'] = find_option('device size with M = 1000\*1000:', hdparm)

    return info


def fs_info(mountpoint):
    info = {}
    mount = run_command('mount')[0]
    dev = None
    for line in mount.split('\n'):
        if re.match('.* %s .* ' % mountpoint, line):
            dev = line.split(' ')[0]
    command = '/sbin/tune2fs -l %s' % dev
    tune2fs = run_command(command.split())[0]
   
    info['name']         = find_option('Filesystem volume name:', tune2fs)
    info['uuid']         = find_option('Filesystem UUID:', tune2fs)
    info['state']        = find_option('Filesystem state:', tune2fs)
    info['created']      = find_option('Filesystem created:', tune2fs)
    info['last_checked'] = find_option('Last checked:', tune2fs)
    info['last_written'] = find_option('Last write time:', tune2fs)

    block_size    = int(find_option('Block size:', tune2fs))
    total_blocks  = int(find_option('Block count:', tune2fs))
    free_blocks   = int(find_option('Free blocks:', tune2fs))
    size          = block_size * total_blocks /1024 /1024
    free          = 100.0 * free_blocks / total_blocks

    info['size']         = '%s MB'  % size
    info['free']         = '%.1f%%' % free

    return info


def os_info():
    info = {}

    hostname = run_command('hostname --fqdn'.split())[0]
    info['hostname'] = hostname.rstrip('\n')
   
    cmd = '/usr/bin/lsb_release'

    info['os_distribution'] = run_command('/usr/bin/lsb_release --id      --short'.split())[0].rstrip('\n')
    info['os_version']      = run_command('/usr/bin/lsb_release --release --short'.split())[0].rstrip('\n')


    motd_voyage = '/etc/motd.voyage'
    motd_tail   = '/etc/motd.tail'
 
    if os.path.isfile(motd_voyage):
        info['os_flavour'] = 'Voyage'

        if os.path.isfile(motd_tail):
            motd = motd_tail
        else:
            motd = motd_voyage
        banner = open(motd, 'r').read()
        info['os_flavour_version'] = find_option('.* Version:', banner)

    return info


def mac_address(dev):
    address_file = '/sys/class/net/%s/address' % dev
    
    if os.path.isfile(address_file):
        return open(address_file).read().split('\n')[0]


def ipv4_address(dev):
    cmd = '/sbin/ip address show %s' % dev
    dev_config = run_command(cmd.split())[0]
    return find_option('inet ', dev_config).split(' ')[0]


def hardware_info():
    info = {}
   
    info['mac_eth0'] = mac_address('eth0')

    #grep -i alix /var/log/dmesg 
    #[    1.424425] alix: system is recognized as "PC Engines ALIX.2 v0.99h"

    dmesg = open('/var/log/dmesg', 'r').read()
    alix = find_option('[ \t\[\]0-9\.]*alix:', dmesg)

    if alix:
        info['board_manufacturer'] = 'PC Engines'
        info['board_model'] = 'ALIX'
        info['board_model_detail'] = alix.split('"')[1]

    return info


def net_info():
    info = {}

    interfaces = run_command('ls /sys/class/net/'.split())[0].split()

    for dev in interfaces:
        info[dev] = {}
        info[dev]['ipv4_address'] = ipv4_address(dev)
        info[dev]['carrier'] = open('/sys/class/net/%s/carrier' % dev).read().split('\n')[0]
        info[dev]['status']  = open('/sys/class/net/%s/operstate' % dev).read().split('\n')[0]

    info['routes'] = {}
    routes = run_command('ip route show'.split())[0]
    info['routes']['default'] = find_option('default', routes)

    return info


def system_info(disk='hda'):
    info = {}

    info['os'] = os_info() 
    info['rootfs'] = fs_info('/')
    info['disk'] = disk_info(disk)
    info['hardware'] = hardware_info()
    info['network'] = net_info()

    return info



def main():
    from pprint import pprint
    pprint(system_info())


if  __name__ =='__main__':main()

