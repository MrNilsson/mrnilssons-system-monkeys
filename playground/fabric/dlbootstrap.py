
import nilsson
from fabric.api import settings, sudo, env, run # task
from fabric.contrib.files import append
from fabric.operations import local

root_keys=['nils.toedtmann']
admin_keys=['nils.toedtmann','joe.short','dan.mauger']
admin_user='admin'
admin_group='adm'

# ToDo: 
#   Bug: when call as 'admin', the root key is appended again
#   configure postfix
#   profiles, e.g. password hash
#   in CentOS: install man
#   install & configure ufw


def dlbootstrap_stage1(hostname):
    '''
    Phase I of DL customization. To be run as 'root'
    '''
    if nilsson.am_not_root():
        raise Exception('FATAL: must be root')

    if not hostname or hostname == 'None':
        hostname = env.host

    nilsson.set_hostname(hostname)
    nilsson.regenerate_ssh_host_keys()

    # Customize root account
    for key in root_keys:
        nilsson.ssh_add_public_key(key, user='root')
    nilsson.push_skeleton(local_path='./files/home-skel/',remote_path='.')

    nilsson.allow_sudo_group()

    nilsson.add_posix_group(admin_group) # should already exist
    nilsson.add_posix_user(admin_user,comment='"Admin user"', primary_group=admin_group, sudo=True)
    for key in admin_keys:
        nilsson.ssh_add_public_key(key, user=admin_user)

    print 'Set new password for user "%s": ' % admin_user
    run('passwd %s' % admin_user)


def dlbootstrap_stage2(vpn_server_ip = '', relayhost='', rootalias=''):
    '''
    Phase II of DL customization. To be executed as 'admin'
    '''
    # Since we will disable the root account, we must not be root!
    if not nilsson.am_not_root():
        raise Exception('FATAL: must be not root')

    # Test we can sudo before we proceed!
    need_sudo = True
    nilsson.nilsson_run('true', use_sudo = need_sudo)

    nilsson.push_skeleton(local_path='./files/home-skel/', remote_path='.')
    nilsson.harden_sshd()
    nilsson.lock_user('root')
    nilsson.pkg_upgrade()

    packages = ['screen', 'man', 'vim']
    nilsson.pkg_install(packages)

    nilsson.setup_postfix(relayhost=relayhost, rootalias=rootalias)
    nilsson.setup_ufw(allow=['ssh'])

    route_command = 'ip route add 172.29.0.0/16 via %s' % vpn_server_ip
    append('/etc/network/interfaces', '        up   %s' % route_command, use_sudo = need_sudo)
    nilsson.nilsson_run(route_command, use_sudo = need_sudo)


def dlbootstrap_stage(hostname, vpn_server_ip = '172.29.2.3', relayhost='relay.dc02.dlnode.com', rootalias='hostmaster@demandlogic.co.uk'):
    with settings(user='root'):
        dlbootstrap_stage1(hostname)

    with settings(user='admin'):
        dlbootstrap_stage2(vpn_server_ip = vpn_server_ip, relayhost=relayhost, rootalias=rootalias)


def dl_setup_relay(networks = ['172.29.0.0/16']):
    '''
    '''
    # TODO: consider special case where relay is NATed and has to do special settings
    nilsson.setup_postfix(networks = networks, interfaces = 'all')
    nilsson.configure_ufw(allow = ['smtp'])

