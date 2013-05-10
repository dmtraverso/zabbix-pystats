#!/usr/bin/python -u

import datetime
import os
import sys
import boto
import json
import re
import string
import socket
import httplib

from optparse import OptionParser
from dns import resolver

TIMEOUT = 3
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
                        # check if it has an HTTP URL for health_check
                        # the format of the health_check target is
                        # PROTOCOL:PORT[:PATH] **we only care about path**
                        health_check = string.split(lb.health_check.target, ":")
                        if len(health_check) == 3:
                            health_uri = health_check[2]
                        else:
                            health_uri = ""
                        for listener in lb.listeners:
                            # store results as dict
                            data.append({'{#ELB_NAME}' : lb.name + "-" +
                                        str(listener.load_balancer_port),
                                        '{#ELB_DNS}' : lb.dns_name,
                                        '{#ELB_PORT}' : listener.load_balancer_port,
                                        '{#ELB_PROTO}' : listener.protocol,
                                        '{#ELB_HOST}' : item.name,
                                        '{#ELB_PATH}' : health_uri})
    except StopIteration:
        pass
    # build JSON for Zabbix
    # https://www.zabbix.com/documentation/2.0/manual/discovery/low_level_discovery
    discovery = {'data' : data}
    print json.dumps(discovery)

def check_endpoint(ip, args):
    proto = args[0]
    port = args[1]
    path = args[2]
    result = {}
    # create a nicer url for messages
    url = str(str.lower(proto) + "://" + ip + ":" + port + path)
    # decide which type of check we should use
    try:
        if proto == "TCP":
            # check TCP
            s = socket.create_connection((ip, port), TIMEOUT)
            result['status'] = "OK"
            result['info'] = "Connection established"
            s.close()
        elif proto == "HTTP" or proto == "HTTPS":
            # check HTTP / HTTPS
            # TODO: add host header
            # headers = {"Host" : host}
            conn = httplib.HTTPConnection(ip, port, timeout=TIMEOUT)
            if proto == "HTTPS":
                conn = httplib.HTTPSConnection(ip, port, timeout=TIMEOUT)
            # default path
            if path == "":
                path = "/ping"
            # make request
            conn.request("GET", path)
            response = conn.getresponse()
            result = {'info' : "HTTP " + str(response.status) + " " + response.reason}
            if response.status == 200:
                # HTTP 200 found
                result['status'] = "OK"
            elif 200 < response.status < 400:
                # redirect was found
                result['status'] = "WARNING"
            elif response.status >= 400:
                # some error ocurred
                result['status'] = "ERROR"
        else:
            # invalid protocol
            sys.exit("ERROR: invalid health_check protocol")
    except (socket.error, socket.timeout, httplib.BadStatusLine) as e:
        result['status'] = "ERROR"
        result['info'] = str(e)
    # Show message with result
    print "%s: %s received for %s" % (result['status'], result['info'], url)

def check_elb():
    # the string should be something like "proto:port:path"
    args = string.split(options.health_check, ":")
    # resolve ip addrs
    try:
        ips = resolver.query(options.check, "A")
    except resolver.NXDOMAIN:
        sys.exit("ERROR: NXDOMAIN response for %s" % options.check)
    # check type of check
    if len(args) == 3:
        for ip in ips:
            check_endpoint(str(ip), args)
    else:
        # invalid string
        sys.exit("ERROR: Invalid health_check string")

def main(argv):
    # Help + option parsing
    usage = "%prog [options] arg"
    parser = OptionParser(usage, add_help_option=False)
    parser.add_option("-d","--discovery", help="discover ELBs for the specified zone",
                       action="store_true", default=False)
    parser.add_option("-z","--zone", help="zone name for discovery. e.g. qa.cloudhub.io")
    parser.add_option("-c","--check", help="raw ELB record to check")
    parser.add_option("-h","--health_check",
                      help="health check string. Must be \"PROTO:Port:[path]\"")
    global options, args
    (options, args) = parser.parse_args()
    if options.discovery:
        if not options.zone:
            parser.error("Missing --zone for ELB discovery")
        else:
            discover_elbs()
    elif options.check:
        if not options.health_check:
            parser.error("Missing --health_check for ELB checks")
        else:
            check_elb()
    else:
        parser.error("Missing mandatory arguments")

if __name__ == "__main__":
    main(sys.argv)
