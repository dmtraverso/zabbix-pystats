#!/usr/bin/python -u

import fcntl
import sys
import time
import os
import urllib2
import json
import pprint
import urlparse
import inspect

from optparse import OptionParser
from datetime import datetime
from subprocess import call

# Constants
CACHE_TTL = 30
MAX_RETRIES = 3
TIMEOUT = 3
VALID_TIME = time.time() - CACHE_TTL
STATS_FILE = "/tmp/" + os.path.splitext(os.path.basename(sys.argv[0]))[0] + ".cache"

# TODO:
#       separate into files
#       remove unnecessary messages
#       return ZBX_UNSOPPORTED in case of failure to stdout
#       show error messages in stderr

def retrieve_stats(url):
    ''' Connectos to the REST API and returns it contents '''
    try:
        # return string with stats
        u = urllib2.urlopen(url, timeout=TIMEOUT)
        stats = u.read()
        # check if it is JSON
        json.loads(stats)
        # return string if ok
        return stats
    except (urllib2.URLError, urllib2.HTTPError) as e:
        print "Failed to retrieve stats: " + str(e.reason)
        return False
    except (ValueError, TypeError):
        # returned string is not JSON
        sys.exit("No JSON object could be decoded")

def write_stats_file(lock=True):
    ''' Locks and write content to the stats file '''
    try:
        # Lock by default
        if lock:
            fcntl.lockf(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        # truncate file contents
        f.truncate()
        # get stats
        stats = retrieve_stats(options.url)
        if stats:
            f.write(stats)
            f.flush()
            f.seek(0)
            return True
        else:
            # delete file to avoid leaving it empty
            f.close()
            os.remove(f.name)
            sys.exit(1)
    except IOError:
        # file is locked by another process
        return False

def print_stat_from_file(stat):
    ''' Locks and reads content from the stats file '''
    try:
        fcntl.lockf(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        # save JSON data
        stats = json.loads(f.read())
        # translate from foo.bar stat, to stats['foo']['bar']
        variable_name = "stats"
        for k in stat.split("."):
            variable_name += "['" + k + "']"
        # not pretty, but it works
        exec 'print %s' % variable_name
        return True
    except IOError:
        # file is locked exclusive by another process
        return False
    except (KeyError):
        sys.exit("[" + stat + "] is not a valid stat")

# Open the stats file
def get_stat(stat):
    ''' Shows the selected stat, taking it from the cache file '''
    retries = 0
    while retries < MAX_RETRIES:
        if os.path.getmtime(f.name) > VALID_TIME:
            # if file is valid, try to read it
            if print_stat_from_file(stat):
                break
        else:
            # if the file is no longer valid, try to write it
            if write_stats_file():
                print_stat_from_file(stat)
                break
        # sleep and increment retries
        retries += 1
        time.sleep(1)
    # write without locking
    else:
        if write_stats_file(lock=False):
            print_stat_from_file(stat)
    return True

# Check replication lag
def check_replication():
    ''' Check replication lag for this host '''
    url_parts = list(urlparse.urlparse(options.url))
    # update the url to get Replication stats
    url_parts[2] = "/replSetGetStatus"
    url = urlparse.urlunparse(url_parts)
    repl_status = json.loads(retrieve_stats(url))
    # search for self and primary ids
    for index, member in enumerate(repl_status['members']):
        if 'self' in member:
            self_id = index
        if member['stateStr'] == "PRIMARY":
            primary_id = index
    # check if ids were found
    if not locals().has_key('self_id') or not locals().has_key('primary_id'):
        sys.exit("Could not find members array")
    stats = {}
    # convert lag to seconds
    stats['replication_lag'] = (repl_status['members'][primary_id]['optime']['t'] - repl_status['members'][self_id]['optime']['t']) / 1000
    stats['replication_status'] = repl_status['members'][self_id]['stateStr']
    # print all replication stats
    for k in stats.keys():
        print "%s:%s" % (k,stats[k])

# Main program
def main():
    # Help + option parsing
    usage = "%prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option("-s","--stat", help="name of the stat you want to get")
    parser.add_option("-u","--url", help="URL to get MongoDB stats from. Default set to http://localhost:28017/serverStatus", default="http://localhost:28017/serverStatus?text=1")
    parser.add_option("-l","--list-stats", help="outputs all stats to stdout", action="store_true", dest="list_stats", default=False)
    parser.add_option("-c","--check", help="check replication", action="store_true", default=False)
    global options, args, f
    (options, args) = parser.parse_args()
    if not options.stat and not options.check and not options.list_stats:
        parser.error("Missing mandatory arguments, either --stat, --list-stats or --check should be specified")
    elif options.list_stats:
        print retrieve_stats(options.url)
    elif options.check:
        check_replication()
    else:
        # open / write cache file
        try:
            if os.path.isfile(STATS_FILE):
                f = open(STATS_FILE, "r+")
            else:
                # the file does not exist, create it
                f = open(STATS_FILE, "w+")
                write_stats_file()
            # we should be ok to get the stat now
            get_stat(options.stat)
        except IOError as e:
            # file could not be created or read
            sys.exit(e)

if __name__ == "__main__":
    main()
