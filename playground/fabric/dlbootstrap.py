
import nilsson
from fabric.api import settings, sudo, env, run # task

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


def dlbootstrap_stage2():
    '''
    Phase II of DL customization. To be executed as 'admin'
    '''
    nilsson.push_skeleton(local_path='./files/home-skel/', remote_path='.')

    # Test we can sudo before we proceed!
    sudo('id')

    nilsson.harden_sshd()
    nilsson.lock_user('root')
    nilsson.pkg_upgrade()

    packages = ['postfix', 'screen', 'man', 'vim']
    if nilsson.distro_flavour() == 'debian':
        packages.append('bsd-mailx')
    elif nilsson.distro_flavour() == 'redhat':
        packages.append('mailx')
    nilsson.pkg_install(packages)

        
