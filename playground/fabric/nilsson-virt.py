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
from fabric.api import sudo, run#, settings, env, prefix, cd, lcd, local # task
from fabric.contrib.files import exists, comment, put #, append, sed, contains
#from fabric.contrib.project import rsync_project
#from re import sub
from random import randint#, choice
#from urllib2 import urlopen


def prepare_redhat():
    if am_not_root():
        raise Exception('FATAL: must be root')

    newhome = '/home.new-%s' % randint(100000,1000000)
    if contains('/proc/self/mounts', 'home'):
        run('rm -fR %s' % newhome)
        run('cp -a /home %s' % newhome)
        run('umount /home')
        run('rmdir /home')
        run('mv %s /home' % newhome)
        backup_orig('/etc/fstab')
        run('sed -e "s,^\(.* /home .*$\),# \\1," -i /etc/fstab')

    if contains('/proc/self/mounts', 'md3'):
        raise Exception('FATAL: md3 still mounted!')

  # run('pvcreate /dev/md3')
  # run('vgcreate vg0 /dev/md3 ; vgscan')
  # run('lvcreate --size 50M --name volume01 vg0')  # Only now /dev/vg0 appears



def install_vmhost(vm_ip_prefix=''):
    need_sudo = am_not_root()

    if not distro_flavour() == 'redhat':
        raise Exception('FATAL: I only support RedHat-style distributions')

    virt_packages = 'bridge-utils libvirt-python libvirt qemu-kvm virt-top tcpdump smartmontools ntp'

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

    # Set IP address if internal VM network
    if vm_ip_prefix:
        vm_ip_prefix_default = '192\.168\.122'
        vm_network_conf   = '/etc/libvirt/qemu/networks/default.xml'
        backup = '.ORIG'
        if exists(vm_network_conf + backup, use_sudo=need_sudo):
            backup =''
        sed('/etc/libvirt/qemu/networks/default.xml', '%s\.' % vm_ip_prefix_default, '%s.' % vm_ip_prefix, use_sudo=need_sudo, backup=backup)
        sed('/etc/libvirt/qemu/networks/default.xml', 'range start="%s\.2"' % vm_ip_prefix, 'range start="%s\.200"' % vm_ip_prefix, use_sudo=need_sudo, backup='')

        nilsson_run('service libvirtd restart', use_sudo=need_sudo)
        nilsson_run('virsh net-destroy default', use_sudo=need_sudo)
        nilsson_run('virsh net-start default', use_sudo=need_sudo)

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
    

