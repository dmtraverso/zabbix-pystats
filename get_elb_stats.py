#!/usr/bin/python -u

import datetime
import os
import sys
import boto
import json
import re
import string

from optparse import OptionParser
from pprint import pprint
from dns import resolver

# TODO:
#       improve comments
#       avoid global variables
#       use boto to get health checks from ELBs in discovery
#       catch boto exceptions
#       extend for different regions
def discover_elbs():
    regex = re.compile(".*\.elb\.amazonaws\.com")
    data = [] # list to store the result
    conn_elb = boto.connect_elb() # used to get ELB specific data
    elbs = conn_elb.get_all_load_balancers() # get all ELBs
    conn_r53 = boto.connect_route53() # used to get Route53 records
    zone = conn_r53.get_hosted_zone_by_name(options.zone)
    # FIX
    if not zone:
        sys.exit("ZBX_NOTSUPPORTED")
    # get clean zone_id, due to https://github.com/boto/boto/issues/448
    id = zone['GetHostedZoneResponse']['HostedZone']['Id'].replace('/hostedzone/','')
    # get all resource records
    result = conn_r53.get_all_rrsets(id)
    try:
        for item in result:
            if item.type == "CNAME":
                # check if matches *.elb.amazonaws.com
                for record in item.resource_records:
                    if regex.match(record):
                        # search ELB by its dns_name property
                        lb = (lb for lb in elbs if lb.dns_name==record).next()
                        for listener in lb.listeners:
                            # store results as dict
                            data.append({'{#ELB_NAME}' : lb.name + "-" +
                                        str(listener.load_balancer_port),
                                        '{#ELB_DNS}' : lb.dns_name,
                                        '{#ELB_PORT}' : listener.load_balancer_port,
                                        '{#ELB_PROTO}' : listener.protocol,
                                        '{#ELB_CHECK}' : lb.health_check.target})
    except StopIteration:
        pass
    # build JSON for Zabbix
    # https://www.zabbix.com/documentation/2.0/manual/discovery/low_level_discovery
    discovery = {'data' : data}
    print json.dumps(discovery)

def check_elb():
    pass
    # get just the name of the ELB
    #elb_name = string.split(options.check, ".")[0]
    ## get ELB configuration and extract its healthcheck
    #c = boto.connect_elb()
    #result = c.get_all_load_balancers(elb_name)
    #for lb in result:
    #    print lb.dns_name
    ## get list of A records from the ELB
    #ips = resolver.query(options.check)
    #for ip in ips:
    #    print ip

def main(argv):
    # Help + option parsing
    usage = "%prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option("-d","--discovery", help="discover ELBs for the specified zone",
                       action="store_true", default=False)
    parser.add_option("-z","--zone", help="zone name for discovery. e.g. qa.cloudhub.io")
    parser.add_option("-c","--check", help="raw ELB record to check")
    global options, args
    (options, args) = parser.parse_args()
    if options.discovery:
        if not options.zone:
            parser.error("Missing --zone for ELB discovery")
        else:
            discover_elbs()
    elif options.check:
        check_elb()
    else:
        parser.error("Missing mandatory arguments")

if __name__ == "__main__":
    main(sys.argv)
