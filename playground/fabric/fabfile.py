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

from fabric.api import sudo, run, settings, env # task
from fabric.contrib.files import exists, append, sed, contains
from re import sub
from random import randint
from urllib2 import urlopen

# @task
def system_info() :
    """
    Displays some general information about the remote system.
    """
    for command in ['hostname --fqdn', 'id', 'uname -a', 'lsb_release --description']:
        run(command)


# @task
def am_i_member_of(groupname) :
    """
    Checks whether the current (remote) user is member of the group given as argument
    """
    return groupname in run("groups").split(' ')


# @task
def test_am_i_member_of() :
    """
    Testing am_i_member_of()
    """
    for group in ['admin', 'dlrun', 'doesnotexist']:
        print 'Am i member of group "%s"? %s' % (group, am_i_member_of(group))


def _nish():
    """
    Non-interactive shell. Removes the '-l' from env.shell, attempting to make 
    the shell non-interactive.
    """
  # from fabric.api import env
    return env.shell.replace(' -l', '')


def _load_keyfile(keyfile=''):
    REMOTE_KEYFILE='https://raw.github.com/nilstoedtmann/sshkeys/master/ssh_keys'
    
    if keyfile:
        f = open( keyfile, 'r' )
    else:
        f = urlopen(REMOTE_KEYFILE)

    keys_dict = {}
    for line in f:
        key_id = line.split()[2]
        keys_dict[key_id] = line

    f.close()

    return keys_dict



def am_not_root():
    '''
    Returns "False" if the fabric user "env.user" is "root", and True otherwise.
    '''
    return not env.user == 'root'


def nilsson_run(command, shell=True, pty=True, combine_stderr=True, use_sudo=False):
    '''
    Like 'run()' with additional boolean argument 'use_sudo'
    '''
    if use_sudo:
        return sudo(command, shell=shell, pty=pty, combine_stderr=combine_stderr)
    else:
        return run( command, shell=shell, pty=pty, combine_stderr=combine_stderr)


def nilsson_sudo(command, shell=True, pty=True, combine_stderr=True, user=None):
    '''
    Uses 'run' instead of 'sudo' if already connect as the target user
    '''
    if ( not user and env.user == 'root' ) or user == env.user :
        return run( command, shell=shell, pty=pty, combine_stderr=combine_stderr)
    else:
        return sudo(command, shell=shell, pty=pty, combine_stderr=combine_stderr, user=user)
    

_run    = nilsson_run
_sudo   = nilsson_sudo



def ssh_add_public_key(keyid, user='', keyfile=''):
    '''
    Append the public ssh key with the given key id to a user's 
    .ssh/authorized_keys file. If no keyfile is give, the default one is 
    used, see REMOTE_KEYFILE in _load_keyfile()
    '''
    keys_dict = _load_keyfile(keyfile=keyfile)

    if isinstance(keyid, list):
        keyids = keyid
    else:
        keyids = [keyid]

    keys_to_append = []
    for keyid in keyids:
        matching_key_ids = []
        for listed_key_id in keys_dict.keys():
            if keyid in listed_key_id:
                matching_key_ids.append(listed_key_id)

        if not matching_key_ids:
            raise Exception('FATAL: Cannot find key with id "%s" in keyfile %s!' % (keyid, keyfile) )

        if len(matching_key_ids) > 1 :
            raise Exception('FATAL: Found multiple matches for "%s" in keyfile %s: %s' % (keyid, keyfile, ' '.join(matching_key_ids)))

        keys_to_append.append(keys_dict[matching_key_ids[0]].rstrip('\n'))

    if user:
        userentry = run('grep "^%s:" /etc/passwd' % user)
        if not userentry:
            raise Exception('FATAL: user "%s" does not exist on remote system!' % user)
        homedir = userentry.split(':')[5]
        ssh_dir = homedir + '/.ssh'
    else:
        user = env.user
        ssh_dir = '.ssh'

    authorized_keys = ssh_dir + '/authorized_keys'
    _sudo('mkdir --parents --mode=700 %s ; touch %s' % (ssh_dir, authorized_keys), user=user )
    for keystring in keys_to_append:
        # TODO: NO SUDO NEEDED if we already are target user
        append(authorized_keys, keystring, use_sudo=am_not_root())


def distro_flavour():
    '''
    Try to determine the linux distribution flavour. So far only supported:
    * debian (Debian, Ubuntu)
    * redhat (RHEL, Fedora, CentOS)
    '''
    FLAVOUR_FILES = { 
        'redhat' : '/etc/redhat-release', 
        'debian' : '/etc/debian_version' 
    }

    for flavour in FLAVOUR_FILES.keys():
        if exists(FLAVOUR_FILES[flavour]):
            return flavour
    return None


def test_distro_flavour():
    '''
    Testing distro_flavour()
    '''
    print distro_flavour()
    return


def add_posix_group(group):
    '''
    Add new Linux group
    '''
    pass


DEFAULT_SHELL = '/bin/bash'

def add_posix_user(username, home=None, create_home=True, group=None, groups=None, system=False, shell=DEFAULT_SHELL):
    '''
    Add new Linux group
    TODO: Have option to push skeleton
    '''
    pass


def set_default_shell(shell=DEFAULT_SHELL):
    '''
    Set the default shell for new users. See DEFAULT_SHELL for its own default value.
    '''
    pass


def set_password(password=None, user=None, unlock=True)
    '''
    Set password of user and unlock the user. If no password is supplied, a random one is generated and returned.
    '''
    pass


def lock_user(user)
    '''
    Lock a user
    '''
    pass


def unlock_user(user)
    '''
    Unlock a user
    '''
    pass


def allow_sudo_group(group=None, nopasswd=False, force=False, dry_run=True):
    '''
    Make sure the given group can sudo any command. If no group is given, the distribution's 
    default sudo group is used (debian flavour: 'sudo'; redhat flavour: 'wheel')

    If we find any sudo entry for the given group, we dont append our statement, unless 
    you set 'force=True'

    Use 'dry_run=True' to see what would happen.
    '''

    FLAVOUR_SUDO_GROUPS = {
        'redhat' : 'wheel',
        'debian' : 'sudo'
    }

    SUDOERS = '/etc/sudoers'
    SUDOERS_TMP = '%s.new-%s' % (SUDOERS, randint(10000,100000))

    need_sudo = am_not_root()

    if not exists(SUDOERS):
        raise Exception('FATAL: Could not find %s - is sudo installed?') % SUDOERS

    # Check that current SUDOERS is OK
    _run('visudo -c', use_sudo=need_sudo)

    if not group :
        group = FLAVOUR_SUDO_GROUPS.get(distro_flavour())
    if not group :
        raise Exception('FATAL: could not determine the linux distribution flavour - Please set a group')

    if nopasswd:
        add_line = '%%%s ALL=(ALL) NOPASSWD:ALL' % group
    else:
        add_line = '%%%s ALL=(ALL) ALL' % group

    print 'INFO: Statement to be added to %s:' % SUDOERS
    print '      >>> %s <<<' % add_line

    # Make idem potent
    if contains(SUDOERS, add_line, exact=True, use_sudo=need_sudo):
        print 'INFO: Statement already in %s, nothing to do.' % SUDOERS
        return

    # See whether there already is some sudo statement for this group
    match = '^[[:space:]]*%%%s[[:space:]]' % group
    match_result = contains(SUDOERS, match, use_sudo=need_sudo)
    if match_result:
        print 'WARN: We already found a statement for group "%s" in %s:' % (group, SUDOERS)
        print '      >>> %s <<<' % match_result

        if not force:
            print 'WARN: Aborting. Set "force=True" if you want to append our statement anyway'
            return
        else:
            print 'WARN: Found "force=True", hence appending anyway.'
    
    # Work on a copy
    _run('cp -a %s %s' % (SUDOERS, SUDOERS_TMP), use_sudo=need_sudo)
    append(SUDOERS_TMP, add_line, use_sudo=need_sudo)

    diff = _run('diff %s %s || true' % (SUDOERS, SUDOERS_TMP), use_sudo=need_sudo)
    print '============ Begin diff %s =============' % SUDOERS
    print diff
    print '============== End diff %s =============' % SUDOERS

    with settings(warn_only=True):
        if _run('visudo -c -f %s' % SUDOERS_TMP, use_sudo=need_sudo).failed:
            _run('rm -f %s' % SUDOERS_TMP, use_sudo=need_sudo)
            raise Exception('FATAL: The new sudoers file we produced had broken syntax! Removed & not proceeding.' )

    if dry_run:
        print 'WARN: Dry run requested, not activating new sudoers'
        _run('rm -f %s' % SUDOERS_TMP, use_sudo=need_sudo)
    else:
        print 'INFO: Activing new sudoers'
        _run('mv %s %s' % (SUDOERS_TMP, SUDOERS), use_sudo=need_sudo)

    return


# @task
def dissect_run(command):
    """
    Displays stdout, stderr and exit code of the given command
    """

    # from fabric.api import run, settings, env

    # http://docs.fabfile.org/en/1.4.0/api/core/operations.html
    # http://stackoverflow.com/questions/4888568/can-i-catch-error-codes-when-using-fabric-to-run-calls-in-a-remote-shell

    # "combine_stderr=False" only works with "pty=False". But most bash profiles
    # and bashrc files invoke commands that need a tty (e.g. "mesg n") and throw
    # "err: stdin: is not a tty". Hence, one should either set "shell=False" or
    # remove the "-l" from "env.shell" to make the shell non-interactive. 
    # See http://docs.fabfile.org/en/1.3.4/faq.html

    print '######################################################'

    # Fabric before May 2011 had a bug: "run().stderr" required "env.combine_stderr=False" 
    # too!  See https://github.com/fabric/fabric/issues/324
    with settings(warn_only=True, shell=_nish(), combine_stderr=False):
        result = run(command, pty=False, combine_stderr=False)

    print 'command     = "%s"' % command
    print 'stdout      = "%s"' % result
    print 'stderr      = "%s"' % result.stderr 
    print 'return_code = "%s"' % result.return_code
    print 'succeeded   = "%s"' % result.succeeded 
    print 'failed      = "%s"' % result.failed
    print ' '



# @task
def test_dissect_run():
    """
    Testing dissect_run()
    """
    print '######################################################'
    print '# No errors, no stderr'
    dissect_run('ls -l /etc/passwd')
    
    print '######################################################'
    print '# Error + stderr'
    dissect_run('ls -l /DOES_NOT_EXIST')



