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

from fabric.api import sudo, run, settings, env, prefix, cd, lcd, local # task
from fabric.contrib.files import exists, append, sed, contains
from fabric.contrib.project import rsync_project
from fabric.operations import put
from re import sub
from random import randint, choice
from urllib2 import urlopen


# Some global definitions
def _NILSSON_FLAVOUR_SUDO_GROUPS():
    return {
        'redhat' : 'wheel',
        'debian' : 'sudo' 
        }


def _NILSSON_DEFAULT_SHELL():
    return '/bin/bash'


def _boolify(var):
    '''
    Convert any type to boolean. Just like bool(), except that the strings 
    'False' and 'None' in any capitalisation return the bool False.
    '''
    if type(var) is str: 
        return not (var.lower() in ['', 'false', 'none'])
    return bool(var)


def _listify(var, separator='+'):
    '''
    If a variable is a string, convert it to a list. Otherwise leave it as it is.
    Allows to enter lists as 'fab' arguments. Default separator is the "+"
    One should not use ',' or ':' as separator (used by fabric). Make sure you
    escape if you use seperators like ';' or '|'.
    '''
    if type(var) is str:
        return var.split(separator)
    return var


def _integrify(var):
    '''
    If a variable is a string, convert it to an integer. Otherwise leave it as it is.
    '''
    if type(var) is str:
        return int(var)
    return var


def test_listify(s):
    '''
    Test _listify()
    '''
    print _listify(s)


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


def patch_file(filename, patchfilename, use_sudo=False):
    '''
    Patch a remote file
    '''

    patchbin = '/usr/bin/patch'
    use_sudo = _boolify(use_sudo)

    if not exists(filename, use_sudo=use_sudo):
        raise Exception('FATAL: Remote file does not exist')

    if not exists(patchbin):
        pkg_install('patch')

    remote_patchfilename = '/tmp/' + patchfilename.split('/')[-1] + '.%s' % randint(100000,1000000)
    rejectname = filename + '.rej'

    put(patchfilename, remote_patchfilename)
    # TODO: Raise exception if patch is not applyable (but only warn only if patch had 
    #       already been applied before)
    with settings(warn_only=True):
        _run('patch --forward %s < %s' % (filename, remote_patchfilename), use_sudo=use_sudo)
    _run('rm %s' % remote_patchfilename)
    if exists(rejectname, use_sudo=use_sudo):
        _run('rm %s' % rejectname, use_sudo=use_sudo)


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


def group_exists(group):
    '''
    Check whether a POSIX group exists
    '''
    with settings(warn_only=True):
        return run('grep -q "^%s:" /etc/group' % group).succeeded


def test_group_exists(group):
    '''
    Check whether a POSIX group exists
    '''
    print group_exists(group)


def add_posix_group(group, system=False):
    '''
    Add new Linux group
    '''

    if group_exists(group):
        print 'WARN: Group already exists, nothing to do for me.'
        return

    GROUPADD_OPTIONS = ''
    if system:
        GROUPADD_OPTIONS += ' --system'
    return _run('groupadd %s %s' % (GROUPADD_OPTIONS, group), use_sudo=am_not_root())


def add_posix_user_to_group(username, group):
    need_sudo = am_not_root()
    _run( 'usermod --append --groups  %s %s ' % (group, username), use_sudo=am_not_root())



def set_default_shell(shell=_NILSSON_DEFAULT_SHELL()):
    '''
    Set the default shell for new users. See _NILSSON_DEFAULT_SHELL() for its own default value.
    '''
    pass


# Stolen from http://stackoverflow.com/questions/101362/how-do-you-generate-passwords
# TODO: Make sure this uses strong randomness 
PASSWORD_LENGTH = 24
PASSWORD_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
def generate_password(length=PASSWORD_LENGTH, chars=PASSWORD_CHARS):
    return ''.join([choice(chars) for i in range(length)])


def set_password(username, password=None, unlock=True):
    '''
    Set password of user and unlock the user. If no password is supplied, a random one is generated and returned.
    '''

    if password:
        return_password = None
    else:
        print 'INFO: Generating new random password'
        password = generate_password()
        return_password = password

    _run('echo "%s:%s" | chpasswd' % (username, password) , use_sudo=am_not_root())

    if unlock:
        unlock_user(username=username)

    return return_password


def lock_user(username):
    '''
    Lock a user
    '''
    return _run('passwd -l %s' % username, use_sudo=am_not_root())


def unlock_user(username):
    '''
    Unlock a user
    '''
    return _run('passwd -u %s' % username, use_sudo=am_not_root())


def user_exists(username):
    '''
    Check whether a user exists.
    '''
    with settings(warn_only=True):
        return run('id %s' % username).succeeded


def test_user_exists(username):
    print user_exists(username)


def add_posix_user(
    username, 
    comment='', 
    primary_group=None, 
    supplementary_groups=[], 
    shell=_NILSSON_DEFAULT_SHELL(),
    home=None, 
    create_home=True, 
    system=False, 
    sudo=False, 
    password=None):
    '''
    Add new Linux user. If no "password" is supplied, a random password is 
    set and returned. Unlock the user.

    Optional options and their defaults: 
        comment='', 
        primary_group=None, 
        supplementary_groups=[], 
        shell=_NILSSON_DEFAULT_SHELL(),
        home=None, 
        create_home=True, 
        system=False, 
        sudo=False, 
        password=None
      
    TODO: 
     * Have option to push skeleton
     * Add expiry date options
    '''

    system = _boolify(system)
    supplementary_groups = _listify(supplementary_groups)

    if sudo:
        sudo_group = _NILSSON_FLAVOUR_SUDO_GROUPS().get(distro_flavour())
        if not sudo_group:
            raise Exception('FATAL: Could not find out distro flavour, hence could not determine the distros sudo group. Please add sudo group manually as additional supplementary group.')
        supplementary_groups.append(sudo_group)


    exists = user_exists(username)
    USERADD_OPTIONS=''

    if exists:
        print 'INFO: User already exists. Modifying user settings (if any), instead of creating a new user.'
        command = 'usermod'
        if home:
            USERADD_OPTIONS += '--move-home  --home %s' % home
        if system:
            print 'WARNING: Only modifying existing owner, cannot change whether or not it is a system user.'
    else:
        command = 'useradd'
        if home:
            USERADD_OPTIONS += ' --home %s' % home
        if create_home:
            USERADD_OPTIONS += ' --create-home'
        else:
            USERADD_OPTIONS += ' -M'
        if system:
            USERADD_OPTIONS += ' --system'

    if comment:
        USERADD_OPTIONS += ' --comment %s' % comment
    if primary_group:
        USERADD_OPTIONS += ' --gid %s' % primary_group
    if supplementary_groups:
        USERADD_OPTIONS += ' --groups %s' % ','.join(supplementary_groups)
    if shell:
        USERADD_OPTIONS += ' --shell %s' % shell
    
    if exists and not USERADD_OPTIONS:
        print 'INFO: user exists and not settings to be modifyed'
        return

    _run( '%s %s %s' % (command, USERADD_OPTIONS, username), use_sudo=am_not_root())

    if not exists:
        return set_password(password=password, username=username)


def allow_sudo_group(group=None, nopasswd=False, force=False, dry_run=False):
    '''
    Make sure the given group can sudo any command. If no group is given, the distribution's 
    default sudo group is used (debian flavour: 'sudo'; redhat flavour: 'wheel')

    If we find any sudo entry for the given group, we dont append our statement, unless 
    you set 'force=True'

    Use 'dry_run=True' to see what would happen.
    '''

    SUDOERS = '/etc/sudoers'
    SUDOERS_TMP = '%s.new-%s' % (SUDOERS, randint(10000,100000))

    need_sudo = am_not_root()

    if not exists(SUDOERS):
        raise Exception('FATAL: Could not find %s - is sudo installed?') % SUDOERS

    # Check that current SUDOERS is OK
    _run('visudo -c', use_sudo=need_sudo)

    if not group :
        group = _NILSSON_FLAVOUR_SUDO_GROUPS().get(distro_flavour())
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


# Stolen from myself
#   https://bitbucket.org/okfn/sysadmin/src/2f318bcc67fa01d78204f12e07f30fa5955a893c/bin/fabfile.py#cl-451
def harden_sshd():
    '''
    Disables root login and password based login via ssh.
    '''
    # TODO: 
    # * Disallow setting of locale
    # * UseDNS no
    # * Revert if success not confirmed after X seconds

    config     = '/etc/ssh/sshd_config'
    config_tmp = '%s.new-%s' % (config, randint(10000,100000))
    backup     = '%s.ORIG' % config
    need_sudo = am_not_root()

    flavour = distro_flavour()
    if flavour == 'redhat':
        servicename = 'sshd'
    elif flavour == 'debian':
        servicename = 'ssh'
    else:
        print 'WARN: Could not determine distro flavour, guessing name of SSH service'
        servicename = 'ssh'

    _run('cp -a %s %s' % (config, config_tmp), use_sudo=need_sudo)

    sed(config_tmp, '^[ \\t#]*(PermitRootLogin)[ \\t]+[yn][eo].*',        '\\1 no', backup='', use_sudo=need_sudo)
    sed(config_tmp, '^[ \\t#]*(PasswordAuthentication)[ \\t]+[yn][eo].*', '\\1 no', backup='', use_sudo=need_sudo)

    diff = _run('diff %s %s || true' % (config, config_tmp), use_sudo=need_sudo) 
    print '============ Begin diff %s =============' % config
    print diff
    print '============== End diff %s =============' % config

    with settings(warn_only=True):
        if _run('sshd -t -f %s' % config_tmp, use_sudo=need_sudo).failed:
            _run('rm -f %s' % config_tmp, use_sudo=need_sudo)
            raise Exception('FATAL: The new SSH config we produced was broken!' )

    if not exists(backup):
        _run('mv %s %s' % (config, backup), use_sudo=need_sudo)
    _run('mv %s %s' % (config_tmp, config), use_sudo=need_sudo)
    _run('service %s restart' % servicename, use_sudo=need_sudo)


def set_hostname(hostname):
    # TODO: reload MTA

    if not hostname or hostname == 'None':
        hostname = env.host

    need_sudo = am_not_root()

    with settings(warn_only=True):
        hosts_entry = run('grep "^127\.0\.1\.1 " /etc/hosts')
    line_to_append = '127.0.1.1 %s' % hostname
    if hosts_entry == line_to_append:
        pass
    elif not hosts_entry:
        # TODO: this should be placed right under the line ^127.0.0.1
        append('/etc/hosts', '127.0.1.1 %s' % hostname, use_sudo=need_sudo)
    else:
        sed('/etc/hosts', '^(127\.0\.1\.1) (.*)$', '\\1 %s \\2' % hostname, use_sudo=need_sudo)

    _run('echo %s > /etc/hostname' % hostname, use_sudo=need_sudo)
    _run('hostname -F /etc/hostname', use_sudo=need_sudo)
    if exists('/etc/mailname'):
        _run('echo %s > /etc/mailname' % hostname, use_sudo=need_sudo)
    
    # Restart logging service
    servicename = 'rsyslog'
    if exists('/etc/init.d/%s' % servicename):
        _run('service %s restart' % servicename, use_sudo=need_sudo)
    else:
        # CentOS<6 and old Ubuntus and some Debians might not use 'rsyslog'
        print 'WARN: Could not identify syslogging service. Please restart manually.'

    # TODO: reload MTA


MATADATA_MAX_HOURS = 12
def pkg_update_metadata(max_hours=MATADATA_MAX_HOURS):
    '''
    Update the package manager's metadata cache
    '''
    # TODO: Determine cache dir from apt/yum config
    max_hours = _integrify(max_hours)

    need_sudo = am_not_root()

    if distro_flavour() == 'debian':
        # TODO: Check age of /var/cache/apt/pkgcache.bin
        metadata='/var/cache/apt/pkgcache.bin'
        max_min = 60 * max_hours
        if _run('find %s -cmin +%s' % (metadata, max_min)):
            _run('apt-get --assume-yes update', use_sudo=need_sudo)
    elif distro_flavour() == 'redhat':
        # No point as long as we dont know how to "yum install" without updating the metadata
        #_run('yum --assumeyes makecache', use_sudo=need_sudo)
        pass
    else:
        raise Exception('FATAL: Could not determine distro flavour (e.g. RedHat- or Debian-style).')


def pkg_clear_cache():
    '''
    Clear package cache
    '''
    need_sudo = am_not_root()

    if distro_flavour() == 'debian':
        _run('apt-get clean', use_sudo=need_sudo)
    elif distro_flavour() == 'redhat':
        _run('yum --assumeyes clean packages', use_sudo=need_sudo)
    else:
        raise Exception('FATAL: Could not determine distro flavour (e.g. RedHat- or Debian-style).')


def pkg_upgrade(max_hours=MATADATA_MAX_HOURS, interactive=False):
    '''
    Update system
    '''
    # TODO: no progress bars in yum

    max_hours   = _integrify(max_hours)
    interactive = _boolify(interactive)

    pkg_update_metadata(max_hours)

    need_sudo = am_not_root()

    options = ''
    prefix_ = ''
    if distro_flavour() == 'debian':
        if not interactive:
            options += ' --assume-yes'
            prefix_ += ' export DEBIAN_FRONTEND=noninteractive'
        with prefix(prefix_):
            _run('apt-get %s upgrade' % options, use_sudo=need_sudo)
    elif distro_flavour() == 'redhat':
        if not interactive:
            options += ' --assumeyes'
        _run('yum %s update' % options, use_sudo=need_sudo)
    else:
        raise Exception('FATAL: Could not determine distro flavour (e.g. RedHat- or Debian-style).')


def pkg_install(packages, max_hours=MATADATA_MAX_HOURS, interactive=False):
    '''
    Install package(s)
    '''
    max_hours   = _integrify(max_hours)
    interactive = _boolify(interactive)
    packages    = ' '.join(_listify(packages))

    pkg_update_metadata(max_hours)

    need_sudo = am_not_root()

    options = ''
    prefix_ = ''
    if distro_flavour() == 'debian':
        if not interactive:
            options += ' --assume-yes'
            prefix_ += ' export DEBIAN_FRONTEND=noninteractive'
        with prefix(prefix_):
            _run('apt-get %s install %s' % (options, packages), use_sudo=need_sudo)
    elif distro_flavour() == 'redhat':
        if not interactive:
            options += ' --assumeyes'
        _run('yum %s install %s' % (options, packages), use_sudo=need_sudo)
    else:
        raise Exception('FATAL: Could not determine distro flavour (e.g. RedHat- or Debian-style).')


def configure_postfix(relayhost=None):
    '''
    Configure postfix as outgoing-only MTA on localhost
    '''

    # TODO: Set root alias!

    postfix_conf='''
myhostname          = # not set, defaults to hostname then
mydomain            = $myhostname
mydestination       = $myhostname, localhost
inet_interfaces     = localhost
mynetworks          = 127.0.0.0/8 
relayhost           =     

alias_maps          = hash:/etc/aliases

mailq_path          = /usr/bin/mailq.postfix
newaliases_path     = /usr/bin/newaliases.postfix
sendmail_path       = /usr/sbin/sendmail.postfix

manpage_directory   = /usr/share/man
readme_directory    = /usr/share/doc/postfix-2.6.6/README_FILES
sample_directory    = /usr/share/doc/postfix-2.6.6/samples
    '''


# TODO: This is not yet idempotent!
def push_skeleton(local_path, remote_path):
    local_path  = local_path.rstrip('/')  + '/'
    remote_path = remote_path.rstrip('/') + '/'
    # rsync_project(remote_dir=remote_path, local_dir=local_path, exclude='*.append')
    rsync_project(remote_dir=remote_path, local_dir=local_path)

    with lcd(local_path):
        append_filenames = local('find -type f -name \*.append', capture=True).split()
        patch_filenames  = local('find -type f -name \*.patch',  capture=True).split()

    if patch_filenames:
        # TODO: make sue "patch" is installed remotely
        pass

    with cd(remote_path):
        for patch_filename in patch_filenames:
            patch_filename = patch_filename[2:]
            filename = sub('.patch$', '', patch_filename)
            # TODO: Make sure 'patch' returns gracefully if file was already patched
            run('patch %s < %s ; rm %s' % (filename, patch_filename, patch_filename))

        for append_filename in append_filenames:
            append_filename = append_filename[2:]
            filename = sub('.append$', '', append_filename)
            # TODO: Find out whether filename already contains append_filename
            run('cat %s >> %s ; rm %s' % (append_filename, filename, append_filename))

            # append_text = open(local_path+file_name, 'r').read()
            #remote_file_name = remote_path + sub('.append$', '', file_name)
            #remote_file_content = run('cat %s' % remote_file_name).replace('\r\n', '\n')




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



