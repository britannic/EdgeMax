firewall {
    all-ping enable
    broadcast-ping enable
    ipv6-receive-redirects disable
    ipv6-src-route disable
    ip-src-route disable
    log-martians enable
    options {
        mss-clamp {
            interface-type all
            mss 1412
        }
    }
    receive-redirects disable
    send-redirects enable
    source-validation disable
    syn-cookies enable
}
interfaces {
    ethernet eth0 {
        address 192.168.1.1/24
        description Local
        duplex auto
        speed auto
        vif 10 {
            address 10.1.1.1/24
            description "Open VLAN 10 for Wifi and LAN"
            mtu 1500
        }
    }
    ethernet eth1 {
        address dhcp
        description Internet
        dhcp-options {
            default-route update
            default-route-distance 210
            name-server update
        }
        duplex auto
        speed auto
    }
    ethernet eth2 {
        address 192.168.2.1/24
        description Apartment
        duplex auto
        speed auto
    }
    loopback lo {
    }
}
service {
    dhcp-server {
        disabled false
        hostfile-update disable
        shared-network-name LAN1 {
            authoritative enable
            subnet 192.168.1.0/24 {
                default-router 192.168.1.1
                dns-server 192.168.1.1
                domain-name orbc2.org
                lease 86400
                start 192.168.1.21 {
                    stop 192.168.1.240
                }
            }
        }
        shared-network-name Wifi-LAN {
            authoritative enable
            subnet 10.1.1.0/24 {
                default-router 10.1.1.1
                dns-server 208.67.222.222
                dns-server 208.67.222.220
                lease 86400
                start 10.1.1.101 {
                    stop 10.1.1.250
                }
            }
        }
        shared-network-name apartment {
            authoritative enable
            subnet 192.168.2.0/24 {
                default-router 192.168.2.1
                dns-server 192.168.2.1
                lease 86400
                start 192.168.2.21 {
                    stop 192.168.2.240
                }
            }
        }
    }
    dns {
        forwarding {
            blacklist {
                dns-redirect-ip 0.0.0.0
                disabled false
                hosts {
                    dns-redirect-ip 0.0.0.0
                    exclude appleglobal.112.2o7.net
                    exclude cdn.visiblemeasures.com
                    exclude googleadservices.com
                    exclude hb.disney.go.com
                    exclude static.chartbeat.com
                    exclude survey.112.2o7.net
                    exclude adobedtm.com
                    exclude coremetrics.com
                    exclude doubleclick.net
                    exclude hulu.com
                    exclude msdn.com
                    include beap.gemini.yahoo.com
                    source zeustracker.abuse.ch/hostfile {
                        description "abuse.ch ZeuS blocklist host file"
                        prefix 127.0.0.1
                        url https://zeustracker.abuse.ch/blocklist.php?download=hostfile
                    }
                }
            }
            cache-size 150
            listen-on eth0
            listen-on eth2
            listen-on eth1
            options listen-address=127.0.0.1
            options bogus-priv
            options localise-queries
            options domain=ashcreek.home
            system
        }
    }
    gui {
        https-port 443
    }
    ssh {
        disable-password-authentication
        port 22
        protocol-version v2
    }
}
system {
    host-name ubnt
    login {
        user tsd {
            authentication {
                encrypted-password $6$mTbSsrrpgWyCk$VKv5c52BVri82dQmEcDWji7IYN1ooI6j4u3MmZnuM2xvgoxXkeDlFlerncM6dqiY/ffsLeuf69E2.NAOwqK7b/
                plaintext-password ""
                public-keys tsd@kh.orbc2.org {
                    key AAAAB3NzaC1yc2EAAAADAQABAAABAQDLgTtQy4XEjjYtwfCMYKFFSheN8dV1L3Suqo/sdsxKcG8Zv/crBvctxF3TRNJWDzU03FrJnwvu0NkDILfhyKKA/kn6ci+nhx4KgMR11img0sdG7QUomDo8UvXljOArfl7EgK1elJP9baVFf7RsD5brv5bPJc4ZJdMGvB4r2iMpSXsOKHTIr8BDaQBuGRsw/HY7mAy44uIUBgJ82KexMSQZPZJTz0m4zYSWTrfNYoQYOy2qHu2N9KueSm6A9O6t4lw3i41IFNaqhyn0mCnBgnC3A8Hhsc7cf5Jb2nGvMJREWzLTsysEbRns7OYcN8m9R4DKBNjjsLD6RXO+1+Gii+Rf
                    type ssh-rsa
                }
            }
            level admin
        }
        user ubnt {
            authentication {
                encrypted-password $6$TJdolE6qIRRdr$JuplHyhrn/Rmue9mJWXoilEVeTzLjciJjjVhQpY6bxVWNuZWKjUv/QgcT4RevWoMWZvkWet5rGuPqRwu8Dzqm/
                plaintext-password ""
                public-keys Neil@mac-ayre.ashcreek.home {
                    key AAAAB3NzaC1yc2EAAAADAQABAAABAQClWPztVCEjjM7qDltQ7qJD+HDq+eIEFOwYvhYL5Idt3W1TmiAXCZZTEfOvGBB25UrFb1xQV/Euct8q4ejUNyD5rLax0wEba4+MkB1iTx36t67t3F4feIh+MIQ1b2WBtmacuT2fYHXTeo5u8jubJG+legO2Qig1xWa7h4nFYtjPi3QyKxXJMGm6vEZrFfjrjYx72f2f6zoogGjdvLR8D6C+QWS7uMG3W7LWQGA5bvo922Vk+SVEk+vTjptxwzimPUbeGOBVS2GvRA5BqA0ASybwBmTwQbdXF3/sCbJrhGOQQDjDxKI3J+7F7rFtQUr/lb6f4hTYrJ+4AL19l1PR3nEf
                    type ssh-rsa
                }
            }
            level admin
        }
    }
    name-server 192.168.10.1
    ntp {
        server 0.ubnt.pool.ntp.org {
        }
        server 1.ubnt.pool.ntp.org {
        }
        server 2.ubnt.pool.ntp.org {
        }
        server 3.ubnt.pool.ntp.org {
        }
    }
    offload {
        ipsec disable
        ipv4 {
            forwarding disable
            pppoe disable
            vlan disable
        }
        ipv6 {
            forwarding disable
            pppoe disable
            vlan disable
        }
    }
    package {
        repository wheezy {
            components "main contrib non-free"
            distribution wheezy
            password ""
            url http://ftp.us.debian.org/debian/
            username ""
        }
        repository wheezy-backports {
            components main
            distribution wheezy-backports
            password ""
            url http://http.us.debian.org/debian
            username ""
        }
        repository wheezy-updates {
            components "main contrib"
            distribution wheezy/updates
            password ""
            url http://security.debian.org/
            username ""
        }
    }
    static-host-mapping {
        host-name bullyboy {
            alias billy
            inet 192.168.42.50
        }
    }
    syslog {
        global {
            facility all {
                level notice
            }
            facility protocols {
                level debug
            }
        }
    }
    task-scheduler {
        task update_blacklists {
            executable {
                path /config/scripts/update-dnsmasq.pl
            }
            interval 6h
        }
    }
    time-zone America/Los_Angeles
}
vpn {
    ipsec {
        auto-firewall-nat-exclude enable
        esp-group FOO0 {
            compression disable
            lifetime 3600
            mode tunnel
            pfs enable
            proposal 1 {
                encryption aes256
                hash md5
            }
        }
        ike-group FOO0 {
            ikev2-reauth no
            key-exchange ikev1
            lifetime 28800
            proposal 1 {
                dh-group 26
                encryption aes256
                hash md5
            }
        }
        ipsec-interfaces {
            interface eth0
            interface eth1
        }
        nat-networks {
            allowed-network 0.0.0.0/0 {
            }
        }
        nat-traversal enable
    }
    l2tp {
        remote-access {
            authentication {
                local-users {
                    username tsd {
                        password TeathKivakcumty(23
                    }
                }
                mode local
            }
            client-ip-pool {
                start 192.168.10.240
                stop 192.168.10.254
            }
            dhcp-interface eth1
            dns-servers {
                server-1 192.168.100.1
            }
            ipsec-settings {
                authentication {
                    mode pre-shared-secret
                    pre-shared-secret IDrosshajCelAus73@
                }
                ike-lifetime 3600
            }
            mtu 1492
        }
    }
    pptp {
        remote-access {
            authentication {
                local-users {
                    username tsd {
                        password SoTeathKivakcumty(23
                    }
                }
                mode local
            }
            client-ip-pool {
                start 192.168.100.250
                stop 192.168.100.253
            }
            dhcp-interface eth1
            dns-servers {
                server-1 208.67.222.222
                server-2 208.67.220.220
            }
            mtu 1452
        }
    }
}


/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:system@4:ubnt-pptp@1:ubnt-util@1:vrrp@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: v1.8.0alpha3.4818779.151023.1404 */
