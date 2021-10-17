#!/usr/bin/env python
import argparse
import datetime
import hashlib
import json
import os
import platform as pl
import stat
import sys
from glob import glob

import pytz
import requests

BUF_SIZE = 65536
VERSION = "0.3"
NAME = "hashlookup-forensic-analyser"
# cache directory name needs to be known between execution of the script
CACHE_DIR = "/tmp/hashlookup-forensic-analyser"  # nosec
headers = {'User-Agent': f'{NAME}/{VERSION}'}
hostname = pl.node()
platform = pl.platform()
when = datetime.datetime.now(pytz.utc)

parser = argparse.ArgumentParser(
    description="Analyse a forensic target to find and report files found and not found in hashlookup CIRCL public service"
)
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
parser.add_argument("-d", "--dir", help="Directory to analyse")
parser.add_argument(
    "--print-all",
    action="store_true",
    help="Print all files result including known and unknown",
)
parser.add_argument(
    "--print-unknown",
    action="store_true",
    help="Print all files unknown to hashlookup service",
)
parser.add_argument(
    "--include-stats", action="store_true", help="Include statistics in the CSV export"
)
parser.add_argument("--format", help="Output format (default is CSV)", default="csv")
parser.add_argument(
    "--cache",
    action="store_true",
    help=f'Enable local cache of known and unknown hashes in {CACHE_DIR}',
    default=False,
)
args = parser.parse_args()

if not args.dir:
    parser.print_help()
    sys.exit(1)

if args.cache:
    os.makedirs(f'{CACHE_DIR}/known/', exist_ok=True)
    os.makedirs(f'{CACHE_DIR}/unknown/', exist_ok=True)


def lookup(value=None):
    if value is None:
        return False
    r = requests.get(
        f'https://hashlookup.circl.lu/lookup/sha1/{value}', headers=headers
    )
    return r.json()


notanalysed_files = []
files = {'known_files': [], 'unknown_files': []}  # type: ignore

stats = {'found': 0, 'unknown': 0, 'excluded': 0}


for fn in [y for x in os.walk(args.dir) for y in glob(os.path.join(x[0], '*'))]:
    if args.verbose:
        sys.stderr.write(
            f'\rAnalysing {fn} - Found {stats["found"]} - Unknown {stats["unknown"]}\n'
        )
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

    knowncachefile = f'{CACHE_DIR}/known/{h}'
    cachefile = f'{CACHE_DIR}/unknown/{h}'
    if args.cache and os.path.isfile(cachefile):
        hresult = {}
    elif args.cache and os.path.isfile(knowncachefile):
        with open(knowncachefile, 'rb') as f:
            hresult = json.load(f)
    else:
        hresult = lookup(value=h)
    if 'SHA-1' not in hresult:
        stats['unknown'] += 1
        files['unknown_files'].append(f'{fn},{h}')
        if args.cache:
            with open(f'{CACHE_DIR}/unknown/{h}', 'wb') as f:
                f.write(b"Unknown")
    else:
        stats['found'] += 1
        files['known_files'].append(f'{fn},{h}')
        if args.cache:
            with open(f'{CACHE_DIR}/known/{h}', 'wb') as f:
                f.write(json.dumps(hresult).encode())

        if args.verbose:
            print(hresult)

# print(notanalysed_files)
if args.format == "csv":
    print('hashlookup_result,filename,sha-1,size')
    if args.print_all:
        for key in files.keys():
            for line in files[key]:
                name = line.split(',')
                fsize = os.path.getsize(name[0])
                filetype = key.split("_")
                print(f"{filetype[0]},{line},{fsize}")

    elif args.print_unknown:
        for line in files['unknown_files']:
            name = line.split(',')
            fsize = os.path.getsize(name[0])
            print(f"unknown,{line},{fsize}")

    if args.include_stats:
        print(
            f'stats,Analysed directory {args.dir} on {hostname} running {platform} at {when}- Found {stats["found"]} on hashlookup.circl.lu - Unknown files {stats["unknown"]} - Excluded files {stats["excluded"]}'
        )
