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
from fabric.contrib.files import exists, comment, uncomment, put #, append, sed, contains
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


def install_vmhost(vm_ip_prefix=''):
    need_sudo = am_not_root()

    if not distro_flavour() == 'redhat':
        raise Exception('FATAL: I only support RedHat-style distributions')

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
    Assumes a /24 network with its lowest 100 IP addresses static, thereafter DHCP
    '''
    for octet in ip_prefix.split('.')[1:]:
        mac_prefix += ':%0.2X' % int(octet)

    hostlist=''
    for octet in range(2,99):
        mac_octet = '%0.2X' % int(octet)
        hostlist += "      <host mac='%s:%s' ip='%s.%s' />\n" % (mac_prefix, mac_octet, ip_prefix, octet,)
    
    template_libvirt_network_default = Template('''
<network>
  <name>$NAME</name>
  <bridge name='$BRIDGE_DEV' />
  <mac address='$MAC_PREFIX:01'/>
  <forward/>
  <ip address='$IP_PREFIX.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='$IP_PREFIX.100' end='$IP_PREFIX.254' />
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


VM_DEFAULT_SIZE = '10G'
def clone_vm(name, original = None, size = VM_DEFAULT_SIZE, mac = None, volume_group = 'vg0', snapshot = False):
    '''
    Clone a VM. There is a default VM to clone. 
    '''
    mac_prefix = '52:54:00:1D:02'
    if not original:
        original = 'precise.dc02.dlnode.com'

    volume = '/dev/' + volume_group + '/' + name
    #if exists(volume):
    #    raise Exception('FATAL: LVM volume already exists')

    need_sudo = am_not_root()
    match = 'mac address=.%s:' % mac_prefix
    if not mac:
        mac_octets = nilsson_run('grep -hio "%s.." /etc/libvirt/qemu/*.xml | sed -e "s,%s,,i"' % (match, match), use_sudo=need_sudo).split()
        ip_octets  = [ int(o, 16) for o in mac_octets]
        ip_octets.sort()
        highest_ip_octet = ip_octets[-1]
        if  highest_ip_octet < 254:
            mac = '%s:%0.2X' % (mac_prefix, highest_ip_octet + 1)
        else:
            print 'WARN: Have to assign random MAC'

    snapshot = _boolify(snapshot)
    if snapshot:
        print 'WARN: Snapshotting has not yet been tested. Not active.'
        print 'Snapshotting LVM volume. Volume group=%s, original volume=%s, new volume=%s, size=%s:' % (volume_group, original, name, size)
        nilsson_run('echo lvcreate  --size %s  --name %s  --snapshot  /dev/%s/%s' % (size, name, volume_group, original), use_sudo=need_sudo)

        print 'Cloning VM configuration %s to %s:' % (original, name) 
        nilsson_run('echo virt-clone --original=%s --name=%s --mac=%s --file=%s --preserve-data' % (original, name, mac, volume))
    else:
        print 'Creating LVM volume. Volume group=%s, Name=%s, size=%s:' % (volume_group, name, size)
        #nilsson_run('lvcreate  --size %s  --name %s  %s' % (size, name, volume_group), use_sudo=need_sudo)

        print 'Cloning VM %s to %s:' % (original, name) 
        nilsson_run('virt-clone --original=%s --name=%s --mac=%s --file=%s' % (original, name, mac, volume), use_sudo=need_sudo)

    print 'INFO: The MAC address of you new VM %s is %s, this might show up here:' % (name, mac)
    print ' '
    nilsson_run('grep -i %s /etc/libvirt/qemu/networks/default.xml' % mac , use_sudo=need_sudo)
    print ' '



def do_bits(ip_prefix):
    need_sudo = am_not_root()
    backup_orig('/etc/ethers', use_sudo=need_sudo)
    backup_orig('/etc/dnsmasq.conf', use_sudo=need_sudo)
    append('/etc/dnsmasq.conf', 'conf-dir=/etc/dnsmasq.d', use_sudo=need_sudo)
    append('/etc/dnsmasq.d/read-ethers', 'read-ethers', use_sudo=need_sudo)
    nilsson_run('service dnsmasq reload', use_sudo=need_sudo)

    
