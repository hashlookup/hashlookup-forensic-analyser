#!/usr/bin/env python
import argparse
import sys
from glob import glob
import os
import hashlib
import requests
import stat
import platform
import datetime
import pytz

BUF_SIZE = 65536
VERSION = "0.1"
NAME = "hashlookup-forensic-analyser"

headers = {'User-Agent': f'{NAME}/{VERSION}'}
hostname = platform.node()
platform = platform.platform()
when = datetime.datetime.now(pytz.utc)

parser = argparse.ArgumentParser(description="Analyse a forensic target to find and report files found and not found in hashlookup CIRCL public service")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
parser.add_argument("-d", "--dir", help="Directory to analyse")
parser.add_argument("--print-all", action="store_true", help="Print all files result including known and unknown")
parser.add_argument("--print-unknown", action="store_true", help="Print all files unknown to hashlookup service")
parser.add_argument("--include-stats", action="store_true", help="Include statistics in the CSV export")

args = parser.parse_args()

if not args.dir:
    parser.print_help()
    sys.exit(1)


def lookup(value=None):
    if value is None:
        return False
    r = requests.get('https://hashlookup.circl.lu/lookup/sha1/{}'.format(value), headers=headers)
    return r.json()


notanalysed_files = []
files = {
    'known_files' : [],
    'unknown_files' : []  
}

stats = {
    'found' : 0,
    'unknown' : 0,
    'excluded' : 0
}


for fn in [y for x in os.walk(args.dir) for y in glob(os.path.join(x[0],  '*'))]:
    if args.verbose:
        sys.stderr.write(f'\rAnalysing {fn} - Found {stats["found"]} - Unknown {stats["unknown"]}')
        sys.stderr.flush()
    if not os.path.exists(fn):
        notanalysed_files.append(f'{fn}/listed-but-no-existing')
        stats['excluded'] += 1
        continue
    else:
        fn_info = os.stat(fn)
    mode = fn_info.st_mode
    if stat.S_ISDIR(mode):
        notanalysed_files.append(f'{fn},dir')
        continue
    elif stat.S_ISSOCK(mode):
        notanalysed_files.append(f'{fn},socket')
        stats['excluded'] += 1
        continue
    elif not os.path.exists(fn):
        notanalysed_files.append(f'{fn},listed-but-no-existing')
        stats['excluded'] += 1
        continue
    sha1 = hashlib.sha1()
    with open(fn, 'rb') as f:
        size = os.fstat(f.fileno()).st_size
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)
    h = sha1.hexdigest().upper()
    hresult = lookup(value = h)
    if 'SHA-1' not in hresult:
        stats['unknown'] += 1
        files['unknown_files'].append(fn)
    else:
        stats['found'] += 1
        files['known_files'].append(fn)
        if args.verbose:
            print(hresult)

#print(notanalysed_files)
if args.print_all:
    [print(f"{key}: {', '.join(files[key])}") for key in files.keys()]
    
elif args.print_unknown:
    [print(f"unknown: {', '.join(files['unknown_files'])}")]

if args.include_stats:
    print(f'stats,Analysed directory {args.dir} on {hostname} running {platform} at {when}- Found {stats["found"]} on hashlookup.circl.lu - Unknown files {stats["unknown"]} - Excluded files {stats["excluded"]}')
#print(unknown_files)
