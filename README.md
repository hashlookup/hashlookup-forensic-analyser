# hashlookup-forensic-analyser

[![lint_python](https://github.com/hashlookup/hashlookup-forensic-analyser/actions/workflows/lint_python.yml/badge.svg)](https://github.com/hashlookup/hashlookup-forensic-analyser/actions/workflows/lint_python.yml)

Analyse a forensic target (such as a directory) to find and report files found and not found from [CIRCL hashlookup public service](https://circl.lu/services/hashlookup/) or the bloom filter from CIRCL hashlookup.
This tool can help a [digital forensic investigator](https://gist.github.com/adulau/e9e95fead4f32ac0fe725cb2a32fdb51) to know the context, origin of specific files during a digital forensic investigation.

# Usage

~~~~
usage: hashlookup-analyser.py [-h] [-v] [-d DIR] [--print-all] [--print-unknown] [--include-stats] [--format FORMAT] [--cache] [--bloomfilter BLOOMFILTER]

Analyse a forensic target to find and report files found and not found in hashlookup CIRCL public service

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output
  -d DIR, --dir DIR     Directory to analyse
  --print-all           Print all files result including known and unknown
  --print-unknown       Print all files unknown to hashlookup service
  --include-stats       Include statistics in the CSV export
  --format FORMAT       Output format (default is CSV)
  --cache               Enable local cache of known and unknown hashes in /tmp/hashlookup-forensic-analyser
  --bloomfilter BLOOMFILTER
                        Specify filename of a bloomfilter in DCSO bloomfilter format
~~~~

## Example

~~~~bash
python3 hashlookup-analyser.py --print-all -d /usr/local/bin/ --include-stats --cache
hashlookup_result,filename,sha-1,size
known,/usr/local/bin/scss,171B3B77F16894C33ADAC884F162A531FB3A3F62,517
known,/usr/local/bin/sass-convert,555BCFEF91F023E634594C5CC46A41B2A0173742,533
known,/usr/local/bin/listen,758A6526DF120C118FB4309B9AC6AB5DAE21FE6F,529
known,/usr/local/bin/nokogiri,C516EF9E51867E1615DA3FDABDAC55B99E16B6A3,541
known,/usr/local/bin/dumppdf.py,9D4596DE611EF8840383DF4E7682378498B13329,12851
known,/usr/local/bin/sass,C92705012D7CE8BC7BEBFA13D7154720B7D19A08,517
unknown,/usr/local/bin/octopress,F3939C055B533201ED2C65CD5E113A3644CF52FC,547
unknown,/usr/local/bin/pyrsa-verify,0ECC95CACCFE73F100B62306B0EC73214B07A4EF,210
unknown,/usr/local/bin/safe_yaml,4376A50A4C705F6AAB9D7B6A10D292C40AE58CC3,547
unknown,/usr/local/bin/gemoji,672785F37185A4154C9159C1A151A7440007FD2A,529
unknown,/usr/local/bin/bayes.rb,DEF8945D48E0557C2EDA5F506BDDA52CB6F870F2,577
unknown,/usr/local/bin/redcarpet,40E0C2E0D33FF42A6A69DA76BAD24EF5FBC3EF5B,547
unknown,/usr/local/bin/shodan,848E102C87A084C1401BB3FE85BF07E2A6EA984A,214
unknown,/usr/local/bin/pyrsa-priv2pub,3C37A0507F51A35EA5969559C051132B94012CEE,233
unknown,/usr/local/bin/jwt,733BE10A7BFCB3CEE5F593C680542ACFB050C902,211
unknown,/usr/local/bin/github-pages,2FA4D8E77E4D92B11C488EBD3BF46E3C9CF28727,565
unknown,/usr/local/bin/f2py,4DD0FD5C23DAB47B2B9F0BC602EA0E7380E0E1AB,216
unknown,/usr/local/bin/f2py3.8,4DD0FD5C23DAB47B2B9F0BC602EA0E7380E0E1AB,216
unknown,/usr/local/bin/tabulate,676B359E35C10404C7D96D3FEC51E1168ED2F5F3,209
unknown,/usr/local/bin/vba_extract.py,5B8C38C90140D15EA0D57DE5FD0BC6C9DF297E78,1813
unknown,/usr/local/bin/jekyll,6569B0B04E681E2FDCE84516336CAB10117F9D1D,529
unknown,/usr/local/bin/pdf2txt.py,C1D9785041216CBC3831D6A5F826B080EC481F32,8338
unknown,/usr/local/bin/rougify,D5F5C89269E1A7F84A983141C5C22AD50CE14F45,527
unknown,/usr/local/bin/summarize.rb,F0E1C3E5DAB10190C1B1E9D6E4665DD33A8FA4C9,585
unknown,/usr/local/bin/camelot,10CC9D468BE06F880F9065D7A34968701D6F2121,208
unknown,/usr/local/bin/kramdown,7DC8F2F6BD1D685817F2795EEC3AAABB2FBE4803,541
unknown,/usr/local/bin/pyrsa-encrypt,956BA954D79A29F1878375639E8F4D392F63B66C,212
unknown,/usr/local/bin/flask,4BCCBDCC6797E5B48D84207B2E71F74F545443E9,208
unknown,/usr/local/bin/jirashell,A7867C26CCD9EE5ABD1E6ED47A84F0A54A88480F,213
unknown,/usr/local/bin/posix-spawn-benchmark,4393D19B57AF71972AAB9D64159C249290806CF7,579
unknown,/usr/local/bin/pyrsa-sign,145A250476DA9D78ADA74E2F5975C3CC34BD3E10,206
unknown,/usr/local/bin/f2py3,4DD0FD5C23DAB47B2B9F0BC602EA0E7380E0E1AB,216
unknown,/usr/local/bin/pyrsa-keygen,4FEC09E57C767CEBEBC9D1F74FC9FC6B056DA0B2,210
unknown,/usr/local/bin/wsdump.py,01D4947AE9CE873A08EC94A910F7928441685B5E,6902
unknown,/usr/local/bin/emailrep,A73D10ED93DA2AA0A5A2A5282CE1BE14A8F6D769,211
unknown,/usr/local/bin/pyrsa-decrypt,57CB2C91C75701E67D734794363BA523E3DCD952,212
unknown,/usr/local/bin/__pycache__/dumppdf.cpython-38.pyc,7F7332186257CB043570296A13F30E43749C79A8,10562
unknown,/usr/local/bin/__pycache__/vba_extract.cpython-38.pyc,BABF747254BED4881368C1148265538F5FE0C756,1202
unknown,/usr/local/bin/__pycache__/pdf2txt.cpython-38.pyc,0C22717A2D2C6676005B99EB6CFF03BF73DAD5A1,6684
unknown,/usr/local/bin/__pycache__/wsdump.cpython-38.pyc,ADD28D31B88E5995A0725A424B415C350726CFD5,6449
stats,Analysed directory /usr/local/bin/ on kolmogorov running Linux-5.10.0-1045-oem-x86_64-with-glibc2.29 at 2021-10-17 15:50:07.299694+00:00- Found 6 on hashlookup.circl.lu - Unknown files 34 - Excluded files 0
~~~~
## Bloom filter

If you don't want to share your lookups online and do faster lookup, hashlookup provides a [bloom filter to download](https://cra.circl.lu/hashlookup/hashlookup-full.bloom).

The file is around 700MB and can be stored locally in your home directory. `hashlookup-analyser` works in the same way, `--bloomfilter` option allows to specify the filename locatoon of the bloom filter.

~~~~
python3 bin/hashlookup-analyser.py --bloomfilter /home/adulau/hashlookup/hashlookup-full.bloom --include-stats -d /bin
~~~~

# License

The software is open source software released under the "Simplified BSD License".

Copyright 2021 Alexandre Dulaunoy

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

