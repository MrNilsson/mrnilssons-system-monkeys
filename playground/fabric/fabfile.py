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

from fabric.api import sudo, run, settings, env
from re import sub


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



