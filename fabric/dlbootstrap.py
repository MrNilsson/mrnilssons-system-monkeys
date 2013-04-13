import nilsson

dl_root_keys=['nils.toedtmann']
dl_admin_keys=['nils.toedtmann','joe.short','dan.mauger']

def dlbootstrap(hostname=None, relayhost='relay.dc02.dlnode.com', rootalias='hostmaster@demandlogic.co.uk'):
    '''
    Call nilsson.customize_host with DL defaults
    '''
    
    nilsson.customize_host(hostname=hostname, regenerate_ssh_keys=True, 
        root_keys=dl_root_keys, admin_keys=dl_admin_keys,
        relayhost=relayhost, rootalias=rootalias)


def dl_setup_relay(networks = ['172.29.0.0/16']):
    '''
    '''
    # TODO: consider special case where relay is NATed and has to do special settings
    nilsson.setup_postfix(networks = networks, interfaces = 'all')
    nilsson.configure_ufw(allow = ['smtp'])

