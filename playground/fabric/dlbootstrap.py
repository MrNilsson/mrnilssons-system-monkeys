
import nilsson
from fabric.api import settings, sudo # run, env, task

root_keys=['nils.toedtmann']
admin_keys=['nils.toedtmann','joe.short','dan.mauger']
admin_user='admin'
admin_group='adm'

# ToDo: 
#   Make dlbootstrap() idempotent. Problem: after being hardened, the root account is unavalable.
#   set hostname (Default: use env.hostname)
#   upgrade
#   install & configure postfix
#   profiles, e.g. password hash
#   Copy over user skeletton


def dlbootstrap(hostname=''):
    with settings(user='root'):
        for key in root_keys:
            nilsson.ssh_add_public_key(key)

        nilsson.allow_sudo_group()

        nilsson.add_posix_group(admin_group) # should already exist
        nilsson.add_posix_user(admin_user,comment='"Admin user"', primary_group=admin_group, sudo=True)
        for key in admin_keys:
            nilsson.ssh_add_public_key(key, user=admin_user)

    with settings(user=admin_user):    
        nilsson.harden_sshd()
        nilsson.lock_user('root')


