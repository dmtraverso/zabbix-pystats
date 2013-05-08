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
    elbs = []
    c = boto.connect_route53()
    zone = c.get_hosted_zone_by_name(options.zone)
    if not zone:
        sys.exit("ZBX_NOTSUPPORTED")
    # get clean zone_id, due to https://github.com/boto/boto/issues/448
    id = zone['GetHostedZoneResponse']['HostedZone']['Id'].replace('/hostedzone/','')
    # get all resource records
    result = c.get_all_rrsets(id)
    for item in result:
        if item.type == "CNAME":
            # check if matches *.elb.amazonaws.com
            for record in item.resource_records:
                if regex.match(record):
                    # store results as dict
                    elbs.append({'{#ELB_NAME}' : record})
    # build JSON for Zabbix
    # https://www.zabbix.com/documentation/2.0/manual/discovery/low_level_discovery
    if len(elbs) > 0:
        discovery = {'data' : elbs}
        print json.dumps(discovery)

def check_elb():
    # get just the name of the ELB
    elb_name = string.split(options.check, ".")[0]
    # get ELB configuration and extract its healthcheck
    c = boto.connect_elb()
    result = c.get_all_load_balancers(elb_name)
    for lb in result:
        print lb.dns_name
    # get list of A records from the ELB
    ips = resolver.query(options.check)
    for ip in ips:
        print ip

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
