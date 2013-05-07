#!/usr/bin/python -u

import datetime
import os
import sys
import boto
import MySQLdb

from optparse import OptionParser

def retrieve_stats():
    c = boto.connect_cloudwatch()
    end   = datetime.datetime.now()
    start = end - datetime.timedelta(minutes=3)
    dimension = {'DBInstanceIdentifier': options.identifier}
    stats = c.get_metric_statistics(
            60,
            start,
            end,
            options.metric,
            'AWS/RDS',
            'Average',
            dimension)
    if len(stats) > 0:
        # sort datapoints based on its timestamp
        stats_sorted = sorted(stats, key=lambda stat: stat['Timestamp'])
        print stats_sorted[-1]['Average']
    else:
        sys.exit("ZBX_UNSUPPORTED")

def check_connection():
    try:
        db = MySQLdb.connect(host=options.check, user=options.username,
                            passwd=options.password, connect_timeout=3)
        c = db.cursor()
        # show databases
        if c.execute("show databases like '%s'" % options.database):
            # execute stat() function from cursor
            print db.stat()
        else:
            print "ERROR: could not find database %s" % options.database
        db.close()
    except MySQLdb.Error as e:
        print "ERROR: %s" %e

def main(argv):
    # Help + option parsing
    usage = "%prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option("-m","--metric", help="name of the metric you want to get")
    parser.add_option("-i","--identifier", help="database indentifier for CloudWatch metrics")
    parser.add_option("-c","--check", help="hostname for connection checking")
    parser.add_option("-d","--database", help="schema to connection checking")
    parser.add_option("-u","--username", help="MySQL username", default="zabbix")
    parser.add_option("-p","--password", help="MySQL password", default="zabbix")
    global options, args, f
    (options, args) = parser.parse_args()
    if options.check:
        if not options.database:
            parser.error("Missing --database for connection checking")
        else:
            check_connection()
    elif options.metric:
        if not options.identifier:
            parser.error("Missing --identifier to get CloudWatch metrics")
        else:
            retrieve_stats()

if __name__ == "__main__":
    main(sys.argv)
