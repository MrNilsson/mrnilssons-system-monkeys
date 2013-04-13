
import nilsson
#from fabric.api import settings, sudo, env, run # task
from fabric.contrib.files import sed
from fabric.operations import put

def setup_stealth_proxy(name='proxy', realm='Welcome to the proxy', contact='hostmaster', htpasswd=''):
    '''
    Install squid and configure as a stealth web proxy with auth
    '''
    need_sudo = nilsson.am_not_root()

    nilsson.pkg_install('squid3')
    
    if not htpasswd:
        raise Exception('FATAL: Need parameter "htpasswd"')

    put(htpasswd, '/etc/squid3/htpasswd', use_sudo=need_sudo)

    conf = '/etc/squid3/squid.conf'
    nilsson.backup_orig(conf, use_sudo = need_sudo)
    put( '../files' + conf, conf, use_sudo=need_sudo)
    sed(conf, 'CFG_PROXY_HOSTNAME',     name,    backup='', use_sudo=need_sudo)
    sed(conf, 'CFG_HOSTMASTER_ADDRESS', contact, backup='', use_sudo=need_sudo)
    sed(conf, 'CFG_PROXY_REALM',        realm,   backup='', use_sudo=need_sudo)

    nilsson.nilsson_run('service squid3 restart', use_sudo=need_sudo)

    nilsson.configure_ufw(allow = ['8213/tcp'])

    conf = '/etc/cron.daily/squid3-usage'
    put( '../files' + conf, conf, use_sudo=need_sudo)
    nilsson.nilsson_run('chmod +x %s' % conf, use_sudo=need_sudo)
