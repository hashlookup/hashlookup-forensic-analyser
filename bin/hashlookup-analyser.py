#!/usr/bin/env python
import argparse
import datetime
import hashlib
import itertools
import json
import os
import platform as pl
import re
import stat
import sys
from glob import glob

import magic
import pytz
import requests

BUF_SIZE = 65536
VERSION = "0.9"
NAME = "hashlookup-forensic-analyser"
# cache directory name needs to be known between execution of the script
CACHE_DIR = "/tmp/hashlookup-forensic-analyser"  # nosec
headers = {'User-Agent': f'{NAME}/{VERSION}'}
hostname = pl.node()
platform = pl.platform()
when = datetime.datetime.now(pytz.utc)
spinner = itertools.cycle(['◰', '◳', '◲', '◱'])

parser = argparse.ArgumentParser(
    description="Analyse a forensic target to find and report files found and not found in hashlookup CIRCL public service."
)
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
parser.add_argument(
    "--extended-debug",
    action="store_true",
    default=False,
    help="Debug file processed along with the mode and type.",
)
parser.add_argument(
    "--progress",
    action="store_true",
    default=True,
    help="Print progress of the file lookup on stderr.",
)
parser.add_argument(
    "--disable-progress",
    action="store_true",
    default=False,
    help="Disable printing progress of the file lookup on stderr.",
)
parser.add_argument("-d", "--dir", help="Directory to analyse.")
parser.add_argument(
    "--report",
    action="store_true",
    help="Generate a report directory including a summary and all the results.",
    default=False,
)
parser.add_argument(
    "--live-linux",
    action="store_true",
    help="View known and unknown files from the live processes (using /proc)",
    default=False,
)
parser.add_argument(
    "--print-all",
    action="store_true",
    help="Print all files result including known and unknown.",
)
parser.add_argument(
    "--print-unknown",
    action="store_true",
    help="Print all files unknown to hashlookup service.",
)
parser.add_argument(
    "--include-stats", action="store_true", help="Include statistics in the CSV export."
)
parser.add_argument("--format", help="Output format (default is CSV).", default="csv")
parser.add_argument(
    "--cache",
    action="store_true",
    help=f'Enable local cache of known and unknown hashes in {CACHE_DIR}.',
    default=False,
)
parser.add_argument(
    "--bloomfilters",
    nargs='+',
    help="Space separated list of filenames of bloomfilters in DCSO bloomfilter format.",
    default=None,
)
args = parser.parse_args()

if args.bloomfilters is not None:
    from flor import BloomFilter

    bfs = []
    for bffile in args.bloomfilters:
        bf = BloomFilter()
        with open(bffile, 'rb') as f:
            bf.read(f)
        if b"6F1C170761C212EFD5004DF7FB36CEAF9FB053F7" in bf:
            bloomfilter_source = "hashlookup-bloomfilter_" + bffile
        else:
            bloomfilter_source = "bloomfilter-file_" + bffile
        bfs.append({'bf': bf, 'bloomfilter_source': bloomfilter_source})

if args.live_linux:
    args.dir = '/proc'
if not args.dir:
    parser.print_help()
    sys.exit(1)

if args.cache:
    os.makedirs(f'{CACHE_DIR}/known/', exist_ok=True)
    os.makedirs(f'{CACHE_DIR}/unknown/', exist_ok=True)


def lookup(value=None):
    if value is None:
        return False

    if args.bloomfilters is not None:
        for bf in bfs:
            if value.encode() in bf['bf']:
                ret = {}
                ret['SHA-1'] = value
                ret['source'] = bf['bloomfilter_source']
                return ret
        return False

    r = requests.get(
        f'https://hashlookup.circl.lu/lookup/sha1/{value}', headers=headers, timeout=5
    )
    return r.json()


def generate_report():
    datefile = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dirname = f"report-hashlookup-{datefile}"
    os.mkdir(dirname)
    markdown = "\n"
    total = stats["analysed"] + stats["excluded"]
    markdown += "![Hashlookup logo](https://avatars.githubusercontent.com/u/91272032?s=200&v=4)\n"
    markdown += "# Overall statistics\n\n"
    markdown += (
        f"Analysed directory {args.dir} on {hostname} running {platform} at {when}.\n\n"
    )
    markdown += f"Run with [hashlookup-forensic-analysed](https://github.com/hashlookup/hashlookup-forensic-analyser) version {VERSION}.\n\n"
    markdown += "|Hashlookup type|Numbers|\n"
    markdown += "|:-------------:|:-----:|\n"
    for stati in stats.keys():
        markdown += f'|{stati}|{stats[stati]}|\n'
    markdown += "\n"
    markdown += " - *found* : File found and known in the [hashlookup database](https://circl.lu/services/hashlookup/).\n"
    markdown += " - *unknown* : File not found in the [hashlookup database](https://circl.lu/services/hashlookup/).\n"
    markdown += " - *excluded* : File excluded from the analysis such as special files or files inaccessible.\n"
    markdown += (
        " - *analysed* : Total file analysed (hashed) without the excluded ones.\n"
    )
    markdown += "\n"
    markdown += "```mermaid\n"
    markdown += (
        f'pie title File statistics by hashlookup-analyser of {total} files found\n'
    )
    for stati in stats.keys():
        if stati == "analysed":
            continue
        markdown += f'    \"{stati} ({stats[stati]})\" : {stats[stati]}\n'
    markdown += "```\n\n"
    markdown += "# Detailed review\n"
    markdown += "Files analysed can be found below sorted by unknown and known files. The result is also available in a [JSON file](full.json).\n"
    markdown += "## Unknown files\n\n"
    markdown += "Files which might require further investigation and analysis are listed below.\n\n"
    markdown += "|Filename|SHA-1 value|\n"
    markdown += "|:-------|:----------|\n"
    for unknown in files['unknown_files']:
        markdown += f'|{unknown["FileName"]}|{unknown["hash"]}|\n'
    markdown += "\n## Known files\n\n"
    markdown += "Files found in hashlookup which might require less investigation and analysis are listed below.\n\n"
    markdown += "|Filename|SHA-1 value|\n"
    markdown += "|:-------|:----------|\n"
    for known in files['known_files']:
        markdown += f'|{known["FileName"]}|[{known["hash"]}](https://hashlookup.circl.lu/lookup/sha1/{known["hash"]})|\n'

    s = dict(sorted(stat_filemagic.items(), key=lambda item: item[1], reverse=True))
    markdown += "\n## MIME types\n"
    markdown += "```mermaid\n"
    markdown += f'pie title MIME types distribution of the {total} files found\n'
    for val in s.keys():
        markdown += f'    \"{val} ({s[val]})\" : {s[val]}\n'
    markdown += "```\n\n"
    markdown += "\n|MIME type|Occurences|\n"
    markdown += "|:--------|:---------|\n"
    for val in s.keys():
        markdown += f'|{val}|{s[val]}|\n'
    f = open(os.path.join(dirname, "summary.md"), "w")
    f.write(markdown)
    f.close()
    f = open(os.path.join(dirname, "full.json"), "w")
    f.write(json.dumps(files))
    f.close()
    return True


notanalysed_files = []
files = {'known_files': [], 'unknown_files': []}  # type: ignore

stats = {'found': 0, 'unknown': 0, 'excluded': 0, 'analysed': 0}

stat_filemagic: dict = {}

if args.progress:
    progress = 0

for fn in [y for x in os.walk(args.dir) for y in glob(os.path.join(x[0], '*'))]:
    if args.verbose:
        sys.stderr.write(
            f'\rAnalysing {fn} - Found {stats["found"]} - Unknown {stats["unknown"]}\n'
        )
        sys.stderr.flush()
    if args.live_linux:
        plive = os.path.normpath(fn).lstrip('/').split('/')
        try:
            plive[1]
            plive[2]
        except IndexError:
            continue
        if re.match(r"\d+", plive[1]) and re.match("exe", plive[2]):
            plive_pid = plive[1]
        else:
            continue

    if not os.path.exists(fn):
        notanalysed_files.append(f'{fn}/listed-but-no-existing')
        stats['excluded'] += 1
        continue
    else:
        fn_info = os.stat(fn)
    mode = fn_info.st_mode
    if args.extended_debug:
        print(f'file={fn}, mode={mode}, finfo={fn_info}')
    if args.progress and not args.disable_progress:
        sys.stderr.write(next(spinner))
        sys.stderr.write(
            f'  - Files analysed={stats["analysed"]}, excluded={stats["excluded"]}, unknown={stats["unknown"]}, found={stats["found"]}\r'
        )
    if stat.S_ISDIR(mode):
        notanalysed_files.append(f'{fn},dir')
        continue
    elif stat.S_ISSOCK(mode):
        notanalysed_files.append(f'{fn},socket')
        stats['excluded'] += 1
        continue
    elif stat.S_ISFIFO(mode):
        notanalysed_files.append(f'{fn},fifo')
        stats['excluded'] += 1
        continue
    elif stat.S_ISBLK(mode):
        notanalysed_files.append(f'{fn},blockdevice')
        stats['excluded'] += 1
        continue
    elif stat.S_ISCHR(mode):
        notanalysed_files.append(f'{fn},chardevice')
        stats['excluded'] += 1
        continue
    elif stat.S_ISDOOR(mode):
        notanalysed_files.append(f'{fn},dooripc')
        stats['excluded'] += 1
        continue
    elif not os.path.exists(fn):
        notanalysed_files.append(f'{fn},listed-but-no-existing')
        stats['excluded'] += 1
        continue
    elif stat.S_ISREG(mode):
        pass
    else:
        notanalysed_files.append(f'{fn},not regular/unknown')
        stats['excluded'] += 1
        continue

    sha1 = hashlib.sha1()  # nosec
    try:
        with open(fn, 'rb') as f:
            try:
                size = os.fstat(f.fileno()).st_size
            except:
                size = 0
                pass
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha1.update(data)
        h = sha1.hexdigest().upper()
    except Exception as e:
        sys.stderr.write(f'Unable to read {e} file {fn}\n')
        notanalysed_files.append(f'{fn},{e}')
        stats['excluded'] += 1
        pass
    with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
        mime_type = m.id_filename(fn)
        if mime_type in stat_filemagic:
            stat_filemagic[mime_type] += 1
        else:
            stat_filemagic[mime_type] = 1

    knowncachefile = f'{CACHE_DIR}/known/{h}'
    cachefile = f'{CACHE_DIR}/unknown/{h}'
    if args.cache and os.path.isfile(cachefile):
        hresult = {}
    elif args.cache and os.path.isfile(knowncachefile):
        with open(knowncachefile, 'rb') as f:
            hresult = json.load(f)
    else:
        hresult = lookup(value=h)
    if hresult is False or 'SHA-1' not in hresult:
        stats['unknown'] += 1
        t = {}
        t['FileName'] = fn
        t['hash'] = h
        if args.live_linux:
            t['pid'] = plive_pid
        files['unknown_files'].append(t)
        if args.cache:
            with open(f'{CACHE_DIR}/unknown/{h}', 'wb') as f:
                f.write(b"Unknown")
    else:
        stats['found'] += 1
        t = {}
        t['FileName'] = fn
        t['hash'] = h
        if args.live_linux:
            t['pid'] = plive_pid
        files['known_files'].append(t)
        if args.cache:
            with open(f'{CACHE_DIR}/known/{h}', 'wb') as f:
                f.write(json.dumps(hresult).encode())
    stats['analysed'] += 1
    if args.verbose:
        print(hresult)

if args.format == "csv":
    if not args.live_linux:
        print('hashlookup_result,filename,sha-1,size')
    else:
        print('hashlookup_result,pid,filename,sha-1,size')
    if args.print_all:
        for key in files.keys():
            for file_object in files[key]:
                fsize = os.path.getsize(file_object['FileName'])
                filetype = key.split("_")
                if not args.live_linux:
                    print(
                        f"{filetype[0]},\"{file_object['FileName']}\",{file_object['hash']},{fsize}"
                    )
                else:
                    print(
                        f"{filetype[0]},\"{file_object['pid']}\",\"{file_object['FileName']}\",{file_object['hash']},{fsize}"
                    )

    elif args.print_unknown:
        for file_object in files['unknown_files']:
            fsize = os.path.getsize(file_object['FileName'])
            if not args.live_linux:
                print(
                    f"unknown,\"{file_object['FileName']}\",\"{file_object['hash']}\",\"{fsize}\""
                )
            else:
                print(
                    f"unknown,\"{file_object['pid']}\",\"{file_object['FileName']}\", \"{file_object['hash']}\",\"{fsize}\""
                )

    if args.include_stats:
        if args.bloomfilters is not None:
            bloomfilter_source = bloomfilter_source
        else:
            bloomfilter_source = "None - live request"
        print(
            f'stats,Analysed directory {args.dir} on {hostname} running {platform} at {when} on a total files of {stats["analysed"]} - Found {stats["found"]} on hashlookup.circl.lu ({bloomfilter_source})- Unknown files {stats["unknown"]} - Excluded files {stats["excluded"]}'
        )

if args.report:
    generate_report()
