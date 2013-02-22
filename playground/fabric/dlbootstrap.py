
import nilsson
from fabric.api import settings, sudo, env, run # task
from fabric.contrib.files import append

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


def dlbootstrap_stage0():
    '''
    Phase 0 of DL customization. To be run as 'root'
    '''
    if nilsson.am_not_root():
        raise Exception('FATAL: must be root')
    nilsson.regenerate_ssh_host_keys()


def dlbootstrap_stage1(hostname):
    '''
    Phase I of DL customization. To be run as 'root'
    '''
    if nilsson.am_not_root():
        raise Exception('FATAL: must be root')

    if not hostname or hostname == 'None':
        hostname = env.host

    nilsson.set_hostname(hostname)

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


def dlbootstrap_stage2(vpn_server_ip = '172.29.2.3', relayhost='relay.dc02.dlnode.com', rootalias='hostmaster@demandlogic.co.uk'):
    '''
    Phase II of DL customization. To be executed as 'admin'
    '''
    need_sudo = nilsson.am_not_root()

    nilsson.push_skeleton(local_path='./files/home-skel/', remote_path='.')

    # Test we can sudo before we proceed!
    nilsson.nilsson_run('id', use_sudo = True)

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

       
def dl_setup_relay(networks = ['172.29.0.0/16']):
    '''
    '''
    # TODO: consider special case where relay is NATed and has to do special settings
    nilsson.setup_postfix(networks = networks, interfaces = 'all')
    nilsson.configure_ufw(allow = ['smtp'])

