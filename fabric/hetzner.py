
from nilsson import *
from nilssonvirt import *

from fabric.decorators import task, hosts
from fabric.api import sudo, run, env, local #, settings, env, prefix, cd, lcd, local # task
from fabric.contrib.console import confirm


@task
@hosts('vmhost4.binode.net')
def main():
    prefix      = '172.28.4'
    vpn_net     = '172.28.0.0/16'

    # Seed known_hosts
    local('ssh root@%s id' % env.host)

    with settings(user = 'root'):
        # Add key to root temporarily
        ssh_add_public_key('nils')
        ssh_add_public_key('baach')

        # On Hetzner EX* (but not EX*0), the big partition is mounted as /home. Turn in a LVM volume group
     #  turn_mount_into_volumegroup('/home','vg0')

        # Disable SElinux on CentOS
        disable_selinux()

    # Nilsify the virtualisation host
    customize_host(
        admin_keys = ['nils.toedtmann','joerg.baach'], 
        rootalias  = 'sharedserver@baach.de',
        setup_firewall=False)

    with settings(user = 'admin'):
        print('%s' % env.host_string)
        install_libvirt_host(vm_ip_prefix=prefix, vpn_net=vpn_net)
        for i in range(2,11):
            sudo('sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 220%02d -j DNAT --to-destination %s.%s:22' % (i,prefix,i))

    print('Now connect with virt-manager to qemu+ssh://admin@%s/system and create the first guest.' % env.host)
    print('Look into %s:/etc/ethers for a suitable MAC address' % env.host)


