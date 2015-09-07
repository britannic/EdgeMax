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
        description Development
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
        shared-network-name Development {
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
                blackhole 0.0.0.0
                exclude msdn.com
                exclude appleglobal.112.2o7.net
                exclude cdn.visiblemeasures.com
                exclude hb.disney.go.com
                exclude googleadservices.com
                exclude hulu.com
                exclude static.chartbeat.com
                exclude survey.112.2o7.net
                source someonewhocares.org {
                    description "Zero based host and domain list"
                    regex "^0.0.0.0\s([-a-z0-9_.]+).*"
                    url http://someonewhocares.org/hosts/zero/
                }
                source winhelp2002.mvps.org {
                    description "Zero based host and domain list"
                    regex "^0.0.0.0\s([-a-z0-9_.]+).*"
                    url http://winhelp2002.mvps.org/hosts.txt
                }
                source www.malwaredomainlist.com {
                    description "127.0.0.1 based host and domain list"
                    regex "^127\.0\.0\.1\s\s\b([-a-z0-9_\.]*)\b[\s]{0,1}"
                    url http://www.malwaredomainlist.com/hostslist/hosts.txt
                }
                source yoyo.org {
                    description "DNSmasq formatted, but with 127.0.0.1 black hole IP"
                    regex "^address=/\b([-a-z0-9_\.]+)\b/127\.0\.0\.1"
                    url http://pgl.yoyo.org/adservers/serverlist.php?hostformat=dnsmasq&showintro=0&mimetype=plaintext
                }
            }
            cache-size 150
            listen-on eth0
            listen-on eth2
            listen-on eth1
            options listen-address=127.0.0.1
            options bogus-priv
            options localise-queries
            options domain=adblock.home
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
        user ubnt {
            authentication {
                encrypted-password
                plaintext-password ""
                public-keys ubnt@ubnt.adblock.home {
                    key <create one!>
                    type ssh-rsa
                }
            }
            level admin
        }
    }
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
    package {
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
                path /config/scripts/update-blacklists-dnsmasq.pl
            }
            interval 1d
        }
    }
    time-zone America/Los_Angeles
}


/* Warning: Do not remove the following line. */
/* === vyatta-config-version: "config-management@1:conntrack@1:cron@1:dhcp-relay@1:dhcp-server@4:firewall@5:ipsec@5:nat@3:qos@1:quagga@2:system@4:ubnt-pptp@1:ubnt-util@1:vrrp@1:webgui@1:webproxy@1:zone-policy@1" === */
/* Release version: v1.8.0alpha1.4802617.150828.1106 */
