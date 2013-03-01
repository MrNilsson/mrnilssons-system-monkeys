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
from fabric.api import sudo, run#, settings, env, prefix, cd, lcd, local # task
from fabric.contrib.files import exists, comment, uncomment, put, append # sed, contains
#from fabric.contrib.project import rsync_project
#from re import sub
from random import randint #, choice
#from urllib2 import urlopen
from string import Template


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


def turn_mount_into_volumegroup(mountpoint,vgname):
    if am_not_root():
        raise Exception('FATAL: must be root')

    device = move_mount_into_rootfs(mountpoint)

    if contains('/proc/self/mounts', device):
        raise Exception('FATAL: device still mounted!')

    run('pvcreate /dev/%s' % device)
    run('vgcreate %s /dev/%s ; vgscan' % (vgname, device))
    run('lvcreate --size 1M --name %s_testvol %s' % (vgname, vgname))  # Only now the volume group appears


def setup_vmhost_iptables(vm_ip_prefix=''):
    need_sudo = am_not_root()

    if not distro_flavour() == 'redhat':
        raise Exception('FATAL: I only support RedHat-style distributions')

    wide_net= '172.29.0.0/16'
    vm_net  = vm_ip_prefix + '.0/24'
    vm_vpn  = vm_ip_prefix + '.3'
    vm_http = vm_ip_prefix + '.5'
    external_interface = 'eth0'

    pkg_install('iptables')
    nilsson_run('service iptables stop', use_sudo=need_sudo)
    nilsson_run('iptables --table nat --append POSTROUTING --out-interface %s --source %s ! --destination %s --jump MASQUERADE' % (external_interface, wide_net, wide_net), use_sudo=need_sudo)
    nilsson_run('iptables --table nat --append PREROUTING   --in-interface %s --protocol udp --dport 1194 --jump DNAT --to-destination %s' % (external_interface, vm_vpn),  use_sudo=need_sudo)
    nilsson_run('iptables --table nat --append PREROUTING   --in-interface %s --protocol tcp --dport   80 --jump DNAT --to-destination %s' % (external_interface, vm_http), use_sudo=need_sudo)
    nilsson_run('iptables --table nat --append PREROUTING   --in-interface %s --protocol tcp --dport  443 --jump DNAT --to-destination %s' % (external_interface, vm_http), use_sudo=need_sudo)
    nilsson_run('service iptables save', use_sudo=need_sudo)

    # Set route to internal net to VPN server
    # TODO: This does actually not work with libvirt :-(
    route = '%s via %s' % (wide_net, vm_vpn)
    nilsson_run('ip route add %s' % route, use_sudo=need_sudo)
    append('/etc/sysconfig/network-scripts/route-virbr0', route, use_sudo=need_sudo)
    


def install_vmhost(vm_ip_prefix=''):
    need_sudo = am_not_root()

    if not distro_flavour() == 'redhat':
        raise Exception('FATAL: I only support RedHat-style distributions')

    # first we need to configure iptables
    setup_vmhost_iptables(vm_ip_prefix = vm_ip_prefix)

    virt_packages = 'bridge-utils libvirt-python libvirt qemu-kvm virt-top python-virtinst tcpdump smartmontools ntp'
    pkg_install(virt_packages.split())

    deactivate_services = 'iscsi iscsid netfs nfslock rpcbind rpcgssd rpcidmapd'
    for service in deactivate_services.split():
        nilsson_run('service %s stop' % service, use_sudo=need_sudo)
        nilsson_run('chkconfig --level 2345 %s off' % service, use_sudo=need_sudo)

    # Configure libvirtd
    with settings(warn_only=True):
        nilsson_run('service libvirtd stop', use_sudo=need_sudo)

    add_posix_group('libvirt')
    add_posix_user_to_group('admin','libvirt')

    patch_file('/etc/libvirt/libvirtd.conf', 'files/etc/libvirtd.conf.patch', use_sudo=need_sudo)

    nilsson_run('service libvirtd start', use_sudo=need_sudo)

    # Configure internal default VM network
    configure_libvirt_network_default(vm_ip_prefix)

    if not exists('/etc/libvirt/storage/vg0.xml', use_sudo=need_sudo):
        nilsson_run('mkdir -p /etc/libvirt/storage', use_sudo=need_sudo)
        put('files/etc/libvirt/storage/vg0.xml', '/etc/libvirt/storage/vg0.xml', use_sudo=need_sudo)
        nilsson_run('virsh pool-define /etc/libvirt/storage/vg0.xml', use_sudo=need_sudo)
        nilsson_run('virsh pool-start vg0', use_sudo=need_sudo)
        nilsson_run('virsh pool-autostart vg0', use_sudo=need_sudo)

    nilsson_run('wget -c --progress=dot -P /var/lib/libvirt/images/ http://old-releases.ubuntu.com/releases/12.04.1/ubuntu-12.04.1-server-amd64.iso', use_sudo=need_sudo)


    # Configure ntp
    ntp_config = '/etc/ntp.conf'
    backup_orig(ntp_config, use_sudo=need_sudo)
    sed(ntp_config, 'hetzner.com', 'hetzner.de', use_sudo=need_sudo, backup='')
    if vm_ip_prefix:
        append(ntp_config, 'restrict %s.0 mask 255.255.255.0' % vm_ip_prefix, use_sudo=need_sudo)
    #append(ntp_config, '# Bla', use_sudo=need_sudo)
    nilsson_run('service ntpd restart', use_sudo=need_sudo)
    

def configure_libvirt_network_default(vm_ip_prefix, mac_prefix = '52:54:00', interface = 'virbr0', name='default'):
    need_sudo = am_not_root()

    vm_network_conf   = '/etc/libvirt/qemu/networks/%s.xml' % name
    vm_network_conf_local = '/tmp/libvirt_network_%s' % name

    localfile = open(vm_network_conf_local, 'w')

    localfile.write(generate_libvirt_network_default(vm_ip_prefix, mac_prefix=mac_prefix, interface=interface, name=name))
    localfile.close()

    backup_orig(vm_network_conf)
    nilsson_run('virsh net-destroy   %s' % name, use_sudo=need_sudo)
    nilsson_run('virsh net-undefine  %s' % name, use_sudo=need_sudo)
    nilsson_run('> %s' % vm_network_conf)

    put(vm_network_conf_local, vm_network_conf, use_sudo=need_sudo)
    nilsson_run('virsh net-define    %s' % vm_network_conf, use_sudo=need_sudo)
    nilsson_run('virsh net-autostart %s' % name, use_sudo=need_sudo)
    nilsson_run('virsh net-start     %s' % name, use_sudo=need_sudo)


def generate_libvirt_network_default(ip_prefix, mac_prefix = '52:54:00', interface = 'virbr0', name='default'):
    '''
    Generate a libvirt/qemu network definition. 
    Assumes a /24 network with its lowest 200 IP addresses static, thereafter DHCP
    '''
    for octet in ip_prefix.split('.')[1:]:
        mac_prefix += ':%0.2X' % int(octet)

    hostlist=''
    for octet in range(2,199):
        mac_octet = '%0.2X' % int(octet)
        hostlist += "      <host mac='%s:%s' ip='%s.%s' />\n" % (mac_prefix, mac_octet, ip_prefix, octet,)
    
    template_libvirt_network_default = Template('''
<network>
  <name>$NAME</name>
  <forward mode='route'/>
  <bridge name='$BRIDGE_DEV' />
  <mac address='$MAC_PREFIX:01'/>
  <ip address='$IP_PREFIX.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='$IP_PREFIX.200' end='$IP_PREFIX.254' />
$HOSTLIST
    </dhcp>
  </ip>
</network>
''')

    return template_libvirt_network_default.safe_substitute(
        NAME       = name,
        BRIDGE_DEV = interface,
        MAC_PREFIX = mac_prefix,
        IP_PREFIX  = ip_prefix,
        HOSTLIST   = hostlist )


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


def assigned_macs():
    '''
    Return list of MAC addresses currently in use by VMs
    '''
    # TODO: read properly as XML!
    need_sudo = am_not_root()

    macs1 = nilsson_run('egrep " *<mac address=" /etc/libvirt/qemu/*.xml | sed -e "s,^.*<mac address=\',," -e "s,\'/>,,"', use_sudo=need_sudo).split()
    macs2 = nilsson_run("ip link sh | grep ether | awk '{print $2}'", use_sudo=need_sudo).split()

    macs = set([ mac.upper() for mac in macs1 + macs2 ])
    return macs


VM_DEFAULT_SIZE = '10G'
def clone_vm(name, original = None, size = VM_DEFAULT_SIZE, mac = None, ip = None, volume_group = 'vg0', snapshot = False):
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

    if not original:
        original = 'precise.dc02.dlnode.com'

    need_sudo = am_not_root()

    snapshot = _boolify(snapshot)
    if snapshot:
        print 'WARN: Snapshotting has not yet been tested. Not active.'
        print 'Snapshotting LVM volume. Volume group=%s, original volume=%s, new volume=%s, size=%s:' % (volume_group, original, name, size)
        nilsson_run('echo lvcreate  --size %s  --name %s  --snapshot  /dev/%s/%s' % (size, name, volume_group, original), use_sudo=need_sudo)

        print 'Cloning VM configuration %s to %s:' % (original, name) 
        nilsson_run('echo virt-clone --original=%s --name=%s %s --file=%s --preserve-data' % (original, name, mac_option, volume))
    else:
        print 'Creating LVM volume. Volume group=%s, Name=%s, size=%s:' % (volume_group, name, size)
        #nilsson_run('lvcreate  --size %s  --name %s  %s' % (size, name, volume_group), use_sudo=need_sudo)

        print 'Cloning VM %s to %s:' % (original, name) 
        nilsson_run('virt-clone --original=%s --name=%s %s --file=%s' % (original, name, mac_option, volume), use_sudo=need_sudo)

    print 'INFO: Name of your new machine: %' % name
    if mac:
        print 'INFO: MAC address of your new machine: %' % mac
    if ip:
        print 'INFO: IP address of your new machine: %' % ip
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

    
