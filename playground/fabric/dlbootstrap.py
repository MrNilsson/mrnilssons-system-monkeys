
import nilsson
from fabric.api import settings, sudo # run, env, task

root_keys=['nils.toedtmann']
admin_keys=['nils.toedtmann','joe.short','dan.mauger']
admin_user='admin'
admin_group='adm'

# ToDo: 
#   Make dlbootstrap() idempotent. Problem: after being hardened, the root account is unavalable.
#   upgrade
#   install & configure postfix
#   profiles, e.g. password hash
#   Copy over user skeletton
#   in CentOS: install man


def dlbootstrap(hostname):
    if not hostname or hostname == 'None':
        hostname = env.host

    for key in root_keys:
        nilsson.ssh_add_public_key(key, user='root')

    nilsson.allow_sudo_group()

    nilsson.add_posix_group(admin_group) # should already exist
    nilsson.add_posix_user(admin_user,comment='"Admin user"', primary_group=admin_group, sudo=True)
    for key in admin_keys:
        nilsson.ssh_add_public_key(key, user=admin_user)

    with settings(user=admin_user):
        nilsson.set_hostname(hostname)
        nilsson.harden_sshd()
        nilsson.lock_user('root')

