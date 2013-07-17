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
from fabric.contrib.files import exists, append, sed, contains, uncomment # put
from fabric.contrib.project import rsync_project
from fabric.operations import put, local
from re import sub, search
from random import randint, choice
from urllib2 import urlopen
from string import Template
from socket import gethostbyname


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


def is_ip_address(s):
    ip_address_pattern = '^[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]\.[12]?[0-9]?[0-9]$'
    if search(ip_address_pattern, s):
        return True
    else:
        return False


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


def nilsson_run(command, shell=True, pty=True, combine_stderr=True, use_sudo=False, warn_only=False):
    '''
    Like 'run()' with additional boolean argument 'use_sudo'
    '''
    with settings(warn_only=warn_only):
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


def test_nilsson_run():
    nilsson_run('ls -l /etc/passwd')
    nilsson_run('ls -l /etc/shadow', warn_only=True)
    nilsson_run('ls -l /etc/group', warn_only=True).succeeded
    print nilsson_run('ls -l /etc/shadow1', warn_only=True).succeeded
    print nilsson_run('ls -l /etc/shadow2', warn_only=True).failed
    nilsson_run('ls -l /etc/shadow3')
    print 'We never get here'


def backup_orig(filename, suffix='.ORIG', use_sudo=False):
    backup = filename + suffix
    if not exists(backup):
        _run('cp -a %s %s' % (filename, backup), use_sudo=use_sudo)


def patch_file(filename, patchfilename, use_sudo=False, backup='.ORIG'):
    '''
    Patch a remote file
    '''

    patchbin = '/usr/bin/patch'
    use_sudo = _boolify(use_sudo)

    if not exists(filename, use_sudo=use_sudo):
        raise Exception('FATAL: Remote file does not exist')

    if not exists(patchbin):
        pkg_install('patch')

    if backup:
        backup_orig(filename, use_sudo=use_sudo)

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


def regenerate_ssh_host_keys(hostname=None, remove_old_keys_from_local_known_hosts=True):
    need_sudo = am_not_root()

    if not hostname:
        hostname = '`cat /etc/hostname`'

    for key_type in ['rsa', 'dsa', 'ecdsa']:
        key_file = '/etc/ssh/ssh_host_%s_key' % key_type
        if exists(key_file):
            print 'Found %s' % key_file
            _run('rm %s %s.pub' % (key_file, key_file), use_sudo=need_sudo)
            _run('ssh-keygen -N "" -t %s -f %s -C %s ' % (key_type, key_file, hostname), use_sudo=need_sudo)
    _run('service ssh restart', use_sudo=need_sudo)

    if remove_old_keys_from_local_known_hosts:
        local('ssh-keygen -R %s' % env.host)
        if not is_ip_address(env.host):
            ip_address = gethostbyname(env.host)
            local('ssh-keygen -R %s' % ip_address)


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
    # TODO: consider redhat case!

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


def upload_string(filename, s, backup=True, use_sudo=False):
    '''
    Put a string into a remote file
    '''
    localfilename = '/tmp/upload-%s-%s' % (filename.split('/')[-1], randint(100000,1000000))
    localfile     = open(localfilename, 'w')
    localfile.write(s)
    localfile.close()

    if backup and exists(filename):
        backup_orig(filename, use_sudo=use_sudo)

    put(localfilename, filename, use_sudo=use_sudo)



def set_rootalias(rootalias, reload_portfix=True):
    '''
    Set root mail alias
    '''
    need_sudo = am_not_root()

    aliases = '/etc/aliases'
    uncomment(aliases, '^root:', use_sudo=need_sudo, backup='.ORIG')
    append(aliases, 'root: %s'% rootalias, use_sudo=need_sudo)
    _run('newaliases', use_sudo=need_sudo)
    if reload_portfix:
        _run('service postfix reload', use_sudo=need_sudo)


def generate_postfix_conf(myhostname = '', relayhost = '', mynetworks = '', inet_interfaces = 'localhost'):
    '''
    Generate basic postfix conf as outgoing-only MTA on localhost
    '''

    if myhostname:
        myhostname = 'myhostname          = %s' % myhostname
    else:
        myhostname = '# myhostname        = '

    template_postfix_maincf = Template('''
$MYHOSTNAME
mydomain            = $myhostname
mydestination       = $myhostname, localhost
inet_interfaces     = $INTERFACES
mynetworks          = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 $MYNETWORKS
relayhost           = $RELAYHOST

alias_maps          = hash:/etc/aliases

mailq_path          = /usr/bin/mailq.postfix
newaliases_path     = /usr/bin/newaliases.postfix
sendmail_path       = /usr/sbin/sendmail.postfix

manpage_directory   = /usr/share/man
readme_directory    = /usr/share/doc/postfix-2.6.6/README_FILES
sample_directory    = /usr/share/doc/postfix-2.6.6/samples
''')

    mynetworks = _listify(mynetworks)
    mynetworks = ' '.join(mynetworks)

    return template_postfix_maincf.safe_substitute(
        MYHOSTNAME = myhostname,
        INTERFACES = inet_interfaces,
        RELAYHOST  = relayhost,
        MYNETWORKS = mynetworks)


def setup_postfix(hostname = '', relayhost = '', networks = '', interfaces = 'localhost', rootalias = ''):
    '''
    Configure postfix as outgoing-only MTA on localhost
    '''
    need_sudo = am_not_root()

    packages = ['postfix']
    if distro_flavour() == 'debian':
        packages.append('bsd-mailx')
    elif distro_flavour() == 'redhat':
        packages.append('mailx')
    pkg_install(packages)

    postconf = generate_postfix_conf(myhostname=hostname, relayhost=relayhost, mynetworks=networks, inet_interfaces=interfaces)

    upload_string('/etc/postfix/main.cf', postconf, use_sudo=need_sudo)

    if rootalias:
        set_rootalias(rootalias, reload_portfix=False)

    _run('service postfix restart', use_sudo=need_sudo)


def setup_ufw(allow=['ssh'], force =  True):
    '''
    Setup ufw firewall
    '''

    need_sudo = am_not_root()

    allow = _listify(allow)
    pkg_install('ufw')

    for service in allow:
        _run('ufw allow %s' % service, use_sudo = need_sudo)

    ufw_option = ''
    if force:
        ufw_option += ' --force'

    _run('ufw %s enable' % ufw_option, use_sudo = need_sudo)


def configure_ufw(allow = [], rules = []):
    '''
    Configure ufw
    '''
    need_sudo = am_not_root()

    allow = _listify(allow)
    rules = _listify(rules)

    for service in allow:
        _run('ufw allow %s' % service, use_sudo = need_sudo)

    for rule in rules:
        _run('ufw %s' % rule, use_sudo = need_sudo)


def setup_munin_node(allow=[]):
    '''
    Install and configure a munin node. Does not include configuration of the munin server!
    '''

    '''
    TODO:
    * Make sure "host=*" is set
    * Insert "cidr_allow" at right place
    * Have a blacklist of unneeded munin plugins, and disable them.
    * Co-configure munin-server
    * Make sure munin-node is in runlevel
    '''

    need_sudo = am_not_root()
    allow = _listify(allow)

    pkg_install('munin-node')

    conf = '/etc/munin/munin-node.conf'
    backup_orig(conf, use_sudo = need_sudo)

    for client_ip in allow:
        if not '/' in client_ip:
            client_ip += '/32'
        append(conf, 'cidr_allow %s' % client_ip, use_sudo = need_sudo)
        configure_ufw(rules = ['allow proto tcp from %s to any port 4949' % client_ip] )

    _run('service munin-node restart', use_sudo = need_sudo)


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


#############################################33
# TODO nilsification: 
#   Bug: when call as 'admin', the root key is appended again
#   configure postfix
#   profiles, e.g. password hash
#   in CentOS: install man
#   install & configure ufw

default_admin_user='admin'
default_admin_group='adm'

def customize_host_stage1(hostname, regenerate_ssh_keys, root_keys, admin_user, admin_group, admin_keys):
    '''
    Phase I of customization. May be run as 'root'
    '''
    need_sudo = am_not_root()

    if not hostname or hostname == 'None':
        hostname = env.host

    set_hostname(hostname)

    if regenerate_ssh_keys:
        regenerate_ssh_host_keys()

    # Customize root account
    for key in root_keys:
        ssh_add_public_key(key, user='root')
    # On some Centos installations, /root/ is 775    
    _run('chmod go-w /root/', use_sudo = am_not_root())

    # TODO: enable pushing of skel for root even when we are not root
    if not need_sudo:
        push_skeleton(local_path='../files/home-skel/',remote_path='.')

    allow_sudo_group()

    add_posix_group(admin_group) # should already exist
    add_posix_user(admin_user,comment='"Admin user"', primary_group=admin_group, sudo=True)
    for key in admin_keys:
        ssh_add_public_key(key, user=admin_user)

    print 'Set new password for user "%s": ' % admin_user
    _run('passwd %s' % admin_user, use_sudo = am_not_root())


def customize_host_stage2(relayhost, rootalias, setup_firewall, harden_ssh):
    '''
    Phase II of customization. To be executed as non-root admin user
    '''
    # Since we will disable the root account, we must not be root!
    if not am_not_root():
        raise Exception('FATAL: must be not root')

    # Test we can sudo before we proceed!
    need_sudo = True
    nilsson_run('true', use_sudo = need_sudo)

    push_skeleton(local_path='../files/home-skel/', remote_path='.')
    harden_sshd()
    lock_user('root')
    pkg_upgrade()

    packages = ['screen', 'man', 'vim']
    pkg_install(packages)

    setup_postfix(relayhost=relayhost, rootalias=rootalias)
    if setup_firewall:
        setup_ufw(allow=['ssh'])


def customize_host( hostname = None, regenerate_ssh_keys = False, root_keys = [],
                    admin_user=default_admin_user, admin_group=default_admin_group, admin_keys = [],
                    relayhost='', rootalias='', setup_firewall = True, harden_ssh = True):

    regenerate_ssh_keys = _boolify(regenerate_ssh_keys)
    setup_firewall      = _boolify(setup_firewall)
    harden_ssh          = _boolify(harden_ssh)
    root_keys           = _listify(root_keys)
    admin_keys          = _listify(admin_keys)
    
    if not hostname:
        if is_ip_address(env.host):
            raise Exception('FATAL: you must provide a hostname, either with the fabric argument "--host", or as extra keyword argument "hostname="!')
        else:
            hostname = env.host

    # Make sure the /home/ Skeletton is only writable by the owner
    local('chmod -R go-w ../files/home-skel/')

    customize_host_stage1(hostname, regenerate_ssh_keys, root_keys, admin_user, admin_group, admin_keys)

    # with settings(user='admin'): DOES NOT WORK when there is an explicit user name already mentioned in host_string
    with settings(host_string='%s@%s' % (admin_user, env.host)):
        customize_host_stage2(relayhost, rootalias, setup_firewall, harden_ssh)



def nilsify_host( hostname = None, root_keys = ['nils.toedtmann'], admin_keys=['nils.toedtmann'], 
    regenerate_ssh_keys = False, relayhost='', rootalias='', setup_firewall = True, harden_ssh = True):

    customize_host( hostname = hostname, regenerate_ssh_keys = regenerate_ssh_keys,
                    root_keys = root_keys, admin_keys = admin_keys,
                    relayhost=relayhost, rootalias=rootalias, setup_firewall = setup_firewall, harden_ssh = harden_ssh)



def setup_openvpn(ca_cert = '', server_sert = ''):
    '''
    Setup a OpenVPN service
    '''
    need_sudo = am_not_root()

    # TODO:
    # Install openvpn
    # configure 
    # restart

    # allow forwarding:
    uncomment('/etc/sysctl.conf', 'net.ipv4.ip_forward=1', backup='.ORIG', use_sudo=need_sudo)
    _run('/sbin/sysctl -p ', use_sudo=need_sudo)

    # No firewalling!
    _run('ufw disable', use_sudo = need_sudo)


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



