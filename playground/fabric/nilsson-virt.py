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
from fabric.contrib.files import exists#, append, sed, contains
#from fabric.contrib.project import rsync_project
#from re import sub
#from random import randint, choice
#from urllib2 import urlopen


def install_vmhost(vm_ip_prefix=''):
    need_sudo = am_not_root()

    if not distro_flavour() == 'redhat':
        raise Exception('FATAL: I only support RedHat-style distributions')

    virt_packages = 'bridge-utils libvirt-python libvirt qemu-kvm virt-top tcpdump smartmontools'

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

    patch_file('/etc/libvirt/libvirtd.conf', 'files/etc/libvirtd.conf.patch', use_sudo=need_sudo, backup='.ORIG')

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


