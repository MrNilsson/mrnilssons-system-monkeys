"""
Mr Nilsson's methods to install and configure libvirt/KVM based 
virtualisation onto a RHEL-flavoured (e.g. CentOS) hardware node.
"""


"""
Copyright 2012 Nils Toedtmann <http://nils.toedtmann.net/>

This file is part of Mr. Nilsson's Little System Monkeys:

    <https://github.com/MrNilsson/mrnilssons-system-monkeys>

Mr. Nilsson's Little System Monkeys is free software: you can 
redistribute it and/or modify it under the terms of the GNU General
Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

Mr. Nilsson's Little System Monkeys is distributed in the hope that
it will be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Mr. Nilsson's Little System Monkeys. If not, see 
<http://www.gnu.org/licenses/>.
"""

from nilsson import *
from nilsson import _boolify

from fabric.decorators import task
from fabric.api import sudo, run#, settings, env, prefix, cd, lcd, local # task
from fabric.contrib.files import exists, comment, uncomment, put, append # sed, contains
#from fabric.contrib.project import rsync_project
#from re import sub
from random import randint #, choice
#from urllib2 import urlopen
from string import Template


@task
def move_mount_into_rootfs(mountpoint):
    if am_not_root():
        raise Exception('FATAL: must be root')

    device = run('egrep "^/dev/.* %s " /proc/self/mounts | cut -d " " -f 1 | cut -d "/" -f 3' % mountpoint)
    if not device:
        print 'WARNING: %s seems not to be a mountpoint' % mountpoint
        return None

    suffix = '%s' % randint(100000,1000000)
    new_dir = '%s.new-%s' % (mountpoint, suffix)
    old_dir = '%s.old-%s' % (mountpoint, suffix)

    run('rm -fR %s' % new_dir)
    run('cp -a %s %s' % (mountpoint,new_dir))
    run('umount %s' % mountpoint)
    run('mv %s %s' % (mountpoint, old_dir))
    with settings(warn_only=True):
        run('rmdir %s' % old_dir)
    run('mv %s %s' % (new_dir, mountpoint))
    backup_orig('/etc/fstab')
    run('sed -e "s,^\(.* %s .*$\),# \\1," -i /etc/fstab' % mountpoint)

    return device


@task
def turn_mount_into_volumegroup(mountpoint,vgname):
    if am_not_root():
        raise Exception('FATAL: must be root')

    device = move_mount_into_rootfs(mountpoint)

    if contains('/proc/self/mounts', device):
        raise Exception('FATAL: device still mounted!')

    run('pvcreate /dev/%s' % device)
    run('vgcreate %s /dev/%s ; vgscan' % (vgname, device))
    run('lvcreate --size 1M --name %s_testvol %s' % (vgname, vgname))  # Only now the volume group appears


@task
def configure_libvirt_lvm_pool(hypervisor, vg):
    '''
    Configure existing LVM group vg for use as libvirt storage pool
    '''
    need_sudo = am_not_root()

    # Fail if libvirt declaration already exists:
    if nilsson_run('virsh --connect %s pool-info %s > /dev/null' % (hypervisor, vg), warn_only=True).succeeded :
        raise Exception('FATAL: libvirt LVM pool decalration with this name already exists!')

    # Fail if vg doesn't exist:
    nilsson_run('vgdisplay %s > /dev/null' % vg, use_sudo=need_sudo)

    vg_tmp  = '/tmp/libvirt-storage-%s.xml' % vg
    vg_conf = Template('''<pool type='logical'>
  <name>$LVM_GROUP</name>
  <target>
    <path>/dev/$LVM_GROUP</path>
  </target>
</pool>
''').safe_substitute(LVM_GROUP = vg)

    upload_string(vg_tmp, vg_conf)
    nilsson_run('virsh --connect %s pool-define    %s' % (hypervisor, vg_tmp))
    nilsson_run('virsh --connect %s pool-autostart %s' % (hypervisor, vg))
    nilsson_run('virsh --connect %s pool-start     %s' % (hypervisor, vg))
    

@task
def install_libvirt_host(vm_ip_prefix='', lvm_pool='vg0', mac_prefix='52:54:00', vm_http_suffix='5', vm_vpn_suffix='3', vpn_net='', configure_iptables=True, external_interface='eth0'):
    need_sudo = am_not_root()

    ####
    # Verify we are on a supported distro
    if not distro_flavour() == 'redhat':
        raise Exception('FATAL: I only support RedHat-style distributions')


    ####
    # Disable SElinux
    disable_selinux() 


    ####
    # Install virtualisation packages
    virt_packages = 'bridge-utils libvirt-python libvirt qemu-kvm virt-top python-virtinst tcpdump smartmontools hdparm cryptsetup-luks acpid ntp nc kpartx'
    pkg_install(virt_packages.split())


    ####
    # Deactivate unneeded services
    deactivate_services = 'iscsi iscsid netfs nfslock rpcbind rpcgssd rpcidmapd'
    for service in deactivate_services.split():
        nilsson_run('service %s stop' % service, use_sudo=need_sudo)
        nilsson_run('chkconfig --level 2345 %s off' % service, use_sudo=need_sudo)


    ####
    # Configure libvirtd
    hypervisor = 'qemu:///system'
    with settings(warn_only=True):
        nilsson_run('service libvirtd stop', use_sudo=need_sudo)
    add_posix_group('libvirt')
    add_posix_user_to_group('admin','libvirt')
    patch_file('/etc/libvirt/libvirtd.conf', '../files/etc/libvirt/libvirtd.conf.patch', use_sudo=need_sudo)
    nilsson_run('service libvirtd start', use_sudo=need_sudo)


    ####
    # Configure LVM storage pool 
    if lvm_pool:
        configure_libvirt_lvm_pool(hypervisor, lvm_pool)


    ####
    # Configure internal default VM network
    vm_net   = vm_ip_prefix + '.0/24'
    dhcp_min = vm_ip_prefix + '.2'
    dhcp_max = vm_ip_prefix + '.199'

    if vm_vpn_suffix:
        if not vpn_net:
            vpn_net = vm_net
        vm_vpn = vm_ip_prefix + '.' + vm_vpn_suffix
        vpn_route = '%s via %s' % (vpn_net, vm_vpn)
        dhcp_option = 'dhcp-option=121,%s,%s'  % (vpn_net, vm_vpn)
    else:
        vpn_route = ''
        dhcp_option = ''

    if vm_http_suffix:
        vm_http = vm_ip_prefix + '.' + vm_http_suffix


    nilsson_run('virsh --connect %s net-destroy   default' % hypervisor)
    nilsson_run('virsh --connect %s net-undefine  default' % hypervisor)
    create_libvirt_bridge(hypervisor, 'default', 'br0', vm_ip_prefix + '.1', route = vpn_route)
    create_libvirt_bridge(hypervisor, 'public',  'br1', '0.0.0.0', netmask = '255.255.255.255')


    ####
    # Configure DHCP & DNS service 'dnsmasq'
    
    pkg_install('dnsmasq')

    dnsmasq_conf = Template('''
interface=$INTERFACE
bind-interfaces
except-interface=lo

read-ethers
no-hosts

dhcp-authoritative
dhcp-range=$DHCP_RANGE
$DHCP_OPTION
''').safe_substitute( 
        INTERFACE   = 'br0',
        DHCP_RANGE  = '%s,%s' % (dhcp_min, dhcp_max),
        DHCP_OPTION = dhcp_option
    )

    nilsson_run('service dnsmasq stop', use_sudo=need_sudo, warn_only=True)
    upload_string('/etc/dnsmasq.conf', dnsmasq_conf, use_sudo=need_sudo)
    upload_string('/etc/ethers', generate_ethers(vm_ip_prefix, min_octet=2, max_octet=99, mac_prefix=mac_prefix), use_sudo=need_sudo)
    nilsson_run('service dnsmasq start', use_sudo=need_sudo, warn_only=True)
    nilsson_run('chkconfig dnsmasq on', use_sudo=need_sudo)


    ####
    # Allow IP forwarding
    sed('/etc/sysctl.conf', '^net.ipv4.ip_forward.*', 'net.ipv4.ip_forward = 1', use_sudo=need_sudo, backup='.ORIG')
    nilsson_run('sysctl -w net.ipv4.ip_forward=1', use_sudo=need_sudo)
    

    ####
    # Reset any existing iptables rules, then configure masquerading & checksum fix for DHCP
    pkg_install('iptables')
    nilsson_run('service iptables stop', use_sudo=need_sudo)
    nilsson_run('iptables --table nat    --append POSTROUTING --out-interface %s --source %s ! --destination %s --jump MASQUERADE' % (external_interface, vm_net,  vm_net), use_sudo=need_sudo)
    nilsson_run('iptables --table mangle --append POSTROUTING --out-interface %s --protocol udp --dport 68 --jump CHECKSUM --checksum-fill' % 'br0', use_sudo=need_sudo)

    if configure_iptables:
        if vm_vpn:
            if not vm_vpn == vpn_net:
                nilsson_run('iptables --table nat --append POSTROUTING --out-interface %s --source %s ! --destination %s --jump MASQUERADE' % (external_interface, vpn_net, vpn_net),   use_sudo=need_sudo)
            nilsson_run('iptables --table nat --append PREROUTING   --in-interface %s --protocol udp --dport 1194 --jump DNAT --to-destination %s' % (external_interface, vm_vpn),  use_sudo=need_sudo)

        if vm_http:
            nilsson_run('iptables --table nat --append PREROUTING   --in-interface %s --protocol tcp --dport   80 --jump DNAT --to-destination %s' % (external_interface, vm_http), use_sudo=need_sudo)
            nilsson_run('iptables --table nat --append PREROUTING   --in-interface %s --protocol tcp --dport  443 --jump DNAT --to-destination %s' % (external_interface, vm_http), use_sudo=need_sudo)

    nilsson_run('service iptables save', use_sudo=need_sudo)



    ####
    # Configure ntpd, and allow local VMs to query it
    ntp_config = '/etc/ntp.conf'
    backup_orig(ntp_config, use_sudo=need_sudo)
    sed(ntp_config, 'hetzner.com', 'hetzner.de', use_sudo=need_sudo, backup='')
    if vm_ip_prefix:
        append(ntp_config, 'restrict %s.0 mask 255.255.255.0' % vm_ip_prefix, use_sudo=need_sudo)
    nilsson_run('service ntpd restart', use_sudo=need_sudo)


    
    ####
    # Download distro images
    for image_url in [
        'http://releases.ubuntu.com/trusty/ubuntu-14.04-server-amd64.iso',
        'http://old-releases.ubuntu.com/releases/precise/ubuntu-12.04.3-server-amd64.iso',
        'http://old-releases.ubuntu.com/releases/precise/ubuntu-12.04.3-alternate-amd64.iso',
        'http://cdimage.debian.org/debian-cd/7.5.0/amd64/iso-cd/debian-7.5.0-amd64-netinst.iso',
        'http://download.fedoraproject.org/pub/fedora/linux/releases/20/Fedora/x86_64/iso/Fedora-20-x86_64-netinst.iso',
        'http://ftp.tu-chemnitz.de/pub/linux/centos/6.5/isos/x86_64/CentOS-6.5-x86_64-minimal.iso'
    ]: 
        nilsson_run('wget -c --progress=dot -P /var/lib/libvirt/images/ %s' % image_url, use_sudo=need_sudo)


@task
def create_libvirt_bridge(hypervisor, name, interface, ip_address, netmask = '255.255.255.0', route = '', destroy_existing=False):
    '''
    Define a bridge interface outside libvirt, and make it known to libvirt
    '''
    need_sudo = am_not_root()

    if_conf = Template('''DEVICE=$INTERFACE
TYPE=Bridge
ONBOOT=yes
DELAY=0
BOOTPROTO=static
IPADDR=$MY_IPADDR
NETMASK=$MY_NETMASK
''').safe_substitute(
        INTERFACE = interface,
        MY_IPADDR = ip_address,
        MY_NETMASK = netmask
    )

    upload_string('/etc/sysconfig/network-scripts/ifcfg-%s' % interface, if_conf, use_sudo=need_sudo)
    if route:
        append('/etc/sysconfig/network-scripts/route-%s' % interface, route, use_sudo=need_sudo )
    nilsson_run('ifup %s' % interface, use_sudo=need_sudo)

    libvirt_bridge_conf = Template('''<network>
  <name>$NAME</name>
  <forward mode='bridge'/>
  <bridge name='$BRIDGE' />
</network>
''').safe_substitute(NAME = name, BRIDGE = interface)

    upload_string('/tmp/libvirt-%s.xml' % name, libvirt_bridge_conf, backup=False)
    nilsson_run('virsh --connect %s net-define    /tmp/libvirt-%s.xml' % (hypervisor, name))
    nilsson_run('virsh --connect %s net-autostart %s' % (hypervisor, name))
    nilsson_run('virsh --connect %s net-start     %s' % (hypervisor, name))


def generate_ethers(ip_prefix, min_octet=2, max_octet=254, mac_prefix = '52:54:00'):
    '''
    Generate the contents of /etc/ethers for a given IP range
    '''

    for octet in ip_prefix.split('.')[1:]:
        mac_prefix += ':%0.2X' % int(octet)

    hostlist=''
    for octet in range(min_octet, max_octet+1):
        mac_octet = '%0.2X' % int(octet)
        hostlist += "%s:%s %s.%s\n" % (mac_prefix, mac_octet, ip_prefix, octet)

    return hostlist


def read_ethers():
    etc_ethers = run('grep -v ^# /etc/ethers').replace('\r\n', '\n').split('\n')
    macs = {}
    ips  = {}
    for line in etc_ethers:
        (mac, ip) = line.split()
        mac = mac.upper()
        macs[mac] = ip
        ips[ip] = mac
    return (macs, ips)


@task
def assigned_macs(echo=False):
    '''
    Return list of MAC addresses currently in use by VMs
    '''
    # TODO: read properly as XML!
    need_sudo = am_not_root()

    macs1 = nilsson_run('egrep " *<mac address=" /etc/libvirt/qemu/*.xml | sed -e "s,^.*<mac address=\',," -e "s,\'/>,,"', use_sudo=need_sudo).split()
    macs2 = nilsson_run("ip link sh | grep ether | awk '{print $2}'", use_sudo=need_sudo).split()

    macs = set([ mac.upper() for mac in macs1 + macs2 ])

    if echo:
        print macs
    return macs


@task
def clone_vm(original, name, size = None, mac = None, ip = None, volume_group = 'vg0', snapshot = False):
    '''
    Clone a VM. There is a default VM to clone.
    '''

    # TODO: Match ip range

    volume = '/dev/' + volume_group + '/' + name
    if exists(volume):
        raise Exception('FATAL: LVM volume already exists')

    if ip and mac:
        raise Exception('FATAL: you cannot set MAC and IP')

    (macs, ips) = read_ethers()
    macs_in_use = assigned_macs()

    if mac:
        mac = mac.upper()
        if mac in macs_in_use:
            raise Exception('FATAL: that MAC address is already in use by one of our VMs!')
        if mac in macs:
            ip = macs[mac]
        else:
            print 'WARN: The MAC is not listed in /etc/ethers. I wont have a static IP address'

    elif ip:
        if not ip in ips:
            raise Exception('FATAL: IP not found in /etc/ethers')
        mac = ips[ip]
        print 'INFO: found MAC %s for IP address %s' % (mac, ip)
        if mac in macs_in_use:
            raise Exception('FATAL: that MAC address is already in use by one of our VMs!')

    else:
        available_macs = macs.keys()
        available_macs.sort()

        print 'Av1: %s' % available_macs
        print 'In use: %s' % macs_in_use
        for used_mac in macs_in_use:
            if used_mac in available_macs:
                available_macs.remove(used_mac)
        print 'Av2: %s' % available_macs

        if available_macs:
            mac = available_macs[0]
            ip = macs[mac]
        else:
            print 'WARN: All macs from /etc/ethers already in use! Assigning random MAC'
        
    if mac:
        mac_option = '--mac=%s' % mac
    else:
        mac_option = ''

    need_sudo = am_not_root()

    snapshot = _boolify(snapshot)
    if snapshot:
        if not size:
            raise Exception('FATAL: If you want to try (untested!) snapshotting, then you have to set "size"')
        print 'WARN: Snapshotting has not yet been tested. Not active.'
        print 'Snapshotting LVM volume. Volume group=%s, original volume=%s, new volume=%s, size=%s:' % (volume_group, original, name, size)
        nilsson_run('echo lvcreate  --size %s  --name %s  --snapshot  /dev/%s/%s' % (size, name, volume_group, original), use_sudo=need_sudo)

        print 'Cloning VM configuration %s to %s:' % (original, name) 
        nilsson_run('echo virt-clone --original=%s --name=%s %s --file=%s --preserve-data' % (original, name, mac_option, volume))
    else:
        #print 'Creating LVM volume. Volume group=%s, Name=%s, size=%s:' % (volume_group, name, size)
        #nilsson_run('lvcreate  --size %s  --name %s  %s' % (size, name, volume_group), use_sudo=need_sudo)

        print 'Cloning VM %s to %s:' % (original, name) 
        nilsson_run('virt-clone --original=%s --name=%s %s --file=%s' % (original, name, mac_option, volume), use_sudo=need_sudo)

    print 'INFO: Name of your new machine: %s' % name
    if mac:
        print 'INFO: MAC address of your new machine: %s' % mac
    if ip:
        print 'INFO: IP address of your new machine: %s' % ip
        return ip
    else:
        return None


def do_bits(ip_prefix):
    need_sudo = am_not_root()
    backup_orig('/etc/ethers', use_sudo=need_sudo)
    backup_orig('/etc/dnsmasq.conf', use_sudo=need_sudo)
    append('/etc/dnsmasq.conf', 'conf-dir=/etc/dnsmasq.d', use_sudo=need_sudo)
    append('/etc/dnsmasq.d/read-ethers', 'read-ethers', use_sudo=need_sudo)
    nilsson_run('service dnsmasq reload', use_sudo=need_sudo)

    
