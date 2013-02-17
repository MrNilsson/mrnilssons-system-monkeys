
import nilsson
from fabric.api import settings, sudo, env # run,  task

root_keys=['nils.toedtmann']
admin_keys=['nils.toedtmann','joe.short','dan.mauger']
admin_user='admin'
admin_group='adm'

# ToDo: 
#   Bug: when call as 'admin', the root key is appended again
#   configure postfix
#   profiles, e.g. password hash
#   Copy over user skeletton
#   in CentOS: install man


def dlbootstrap(hostname):
    if not hostname or hostname == 'None':
        hostname = env.host

    for key in root_keys:
        nilsson.ssh_add_public_key(key, user='root')
    nilsson.push_skeleton(local_path=../home-skel/,remote_path=.)

    nilsson.allow_sudo_group()

    nilsson.add_posix_group(admin_group) # should already exist
    nilsson.add_posix_user(admin_user,comment='"Admin user"', primary_group=admin_group, sudo=True)
    for key in admin_keys:
        nilsson.ssh_add_public_key(key, user=admin_user)

    with settings(user=admin_user):
        nilsson.push_skeleton(local_path=../home-skel/,remote_path=.)
        nilsson.set_hostname(hostname)
        nilsson.harden_sshd()
        nilsson.lock_user('root')
        nilsson.pkg_upgrade()

        packages = ['postfix', 'screen', 'man']
        if nilsson.distro_flavour() == 'debian':
            packages.append('bsd-mailx')
        elif nilsson.distro_flavour() == 'redhat':
            packages.append('mailx')
        nilsson.pkg_install(packages)

