#!/usr/bin/env python
import subprocess
import syslog
from logging import *
from urllib2 import *
from netaddr import *
from re import *
"""
---------------------------------------------------------------
 Get remote bogon list and add to ipset
 ipset bogon list updater v1.0
---------------------------------------------------------------

 ipset create ipv4Bogons hash:net family inet

 iptables -I INPUT 1 -i eth0 -m set --match-set banned_ipv4_net src -j DROP

---------------------------------------------------------------
"""
IPSET_PATH                     = "/sbin/ipset"
# IPV4_NETS_URL                = ["http://dshield.org/block.txt"]
IPV4_NETS_URL                  = ["http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"]
#---------------------------------------------------------------
syslog.openlog(ident="THREAT UPDATE", logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)

# LOG_FILENAME                 = '/var/log/user/bogon_update.log'
# logging.basicConfig(filename = LOG_FILENAME,
#                     level=logging.INFO,
#                     format='%(asctime)s %(message)s',
#                     )

#---------------------------------------------------------------
def get_v4_ip_and_subnet_list(data):

    outputlist                 = list()
    outputlist += [IPNetwork(i) for i in re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/?[0-9]{1,2}?\b',data)]
    return sorted(set(cidr_merge(outputlist)))

#---------------------------------------------------------------
class Ipset:
    """
        Manage ipset entry Read/Add/Delete
    """
    #---------------------------------------------------------------
    def __init__(self, inet):
        self.setname           = "ipv4Bogons"                 # ipset chain name
        self.inet              = inet                         # inet mode
        self.ripset            = re.compile(r"^\d")           # ipset regexp
        self.currentstor       = set()                        # ipset stor

    #---------------------------------------------------------------
    def process(self, netlist):
        """
            Process the blocklist data downloaded
        """
        self.read()

        deleted                = self.currentstor.difference(netlist)
        added                  = netlist.difference(self.currentstor)
        same                   = netlist.intersection(self.currentstor)

        for ip in deleted:
            self.del_ip(ip)

        for ip in added:
            self.add_ip(ip)

        syslog.syslog(syslog.LOG_INFO, "%s net | Add : %s | Dup : %s | Del : %s" % (self.inet, len(added), len(same), len(deleted)))

    #---------------------------------------------------------------
    def read(self):
        """
            read and parse current ipset list content
        """
        cmd                    = [IPSET_PATH, "list", self.setname]
        result                 = subprocess.check_output(cmd)
        data                   = result.decode("utf-8")

        for item in data.split("\n"):
            if self.ripset.match(item):
                self.currentstor.add(item.strip())

    #---------------------------------------------------------------
    def add_ip(self, ip):
        """
            add ip to ipset
        """
        cmd                    = [IPSET_PATH, "add", "-q", "-!", self.setname, str(ip)]
        subprocess.call(cmd)

    #---------------------------------------------------------------
    def del_ip(self, ip):
        """
            del ip to ipset
        """
        cmd                    = [IPSET_PATH, "del", "-q", "-!", self.setname, str(ip)]
        subprocess.call(cmd)

#---------------------------------------------------------------
class Updater:
    """
        Download and Parse files
    """
    #---------------------------------------------------------------
    def __init__(self, url, mode):
        self.urls              = url                                              # download url
        self.oip               = Ipset(mode)                                      # ipset object
        self.rethreat          = re.compile(r"(^([0-9]{1,3}\.){3}[0-9]{1,3}).*$") # emerging threats regexp
        self.currentstor       = set()                                            # downloaded ip stor

    #---------------------------------------------------------------
    def download(self, url):
        """
            Download Files and launch parser
        """
        try:
            req                = Request(url)
            data               = urlopen(req)
            code               = data.getcode()

            if code == 200:
                urlsplit       = re.split("/", url)
                filename       = urlsplit[len(urlsplit)-1]
                if filename == "emerging-Block-IPs.txt":
                    self.parse_ethreats_txt(data.read())
                elif filename == "TorBulkExitList.py?ip=1.1.1.1":
                    self.parse_ethreats_txt(data.read())
                elif filename == "anonymous-proxy-fraudulent-ip-address-list":
                    self.parse_ethreats_txt(data.read())
                elif filename == "blist.php":
                    self.parse_ethreats_txt(data.read())

        except HTTPError as error:
            syslog.syslog(syslog.LOG_ERR, "HTTP Error: %s %s" % (error.code, url))
        except URLError as error:
            syslog.syslog(syslog.LOG_ERR, "URL Error: %s %s" % (error.reason, url))

    #---------------------------------------------------------------
    def parse_ethreats_txt(self, data):
        """
            Parse emerging threats IP addresses
        """
        dec                    = get_v4_ip_and_subnet_list(data.decode("utf-8"))
        for line in dec:
            if self.rethreat.match(str(line)):
                self.currentstor.add(str(line).strip())

#---------------------------------------------------------------
    def run(self):
        """
            main run func
        """
        for url in self.urls:
            self.download(url)

        if len(self.currentstor) != 0:
            self.oip.process(self.currentstor)
        else:
            syslog.syslog(syslog.LOG_NOTICE, "Download failed!")

#---------------------------------------------------------------
if __name__ == "__main__":
    syslog.syslog(syslog.LOG_NOTICE, "Starting emerging threats update...")
    Updater(IPV4_NETS_URL, "ipv4").run()
    syslog.syslog(syslog.LOG_NOTICE, "Emerging threats update completed.")
    syslog.closelog()
#     if Updater(IPV4_IPS_URL, "ips").run():
#         logging.info('Successfully updated banned_ipv4_ips list.')
#     else:
#         logging.error('Problem updating banned_ipv4_ips list!')
