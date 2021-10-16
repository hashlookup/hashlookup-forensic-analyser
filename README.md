# hashlookup-forensic-analyser

Analyse a forensic target (such as a directory) to find and report files found and not found from [CIRCL hashlookup public service](https://circl.lu/services/hashlookup/).
This tool can help a digital forensic investigator to know the context, origin of specific files during a digital forensic investigation.

# Usage

~~~~
usage: hashlookup-analyser.py [-h] [-v] [-d DIR] [--print-all] [--print-unknown] [--include-stats] [--format FORMAT]

Analyse a forensic target to find and report files found and not found in hashlookup CIRCL public service

optional arguments:
  -h, --help         show this help message and exit
  -v, --verbose      Verbose output
  -d DIR, --dir DIR  Directory to analyse
  --print-all        Print all files result including known and unknown
  --print-unknown    Print all files unknown to hashlookup service
  --include-stats    Include statistics in the CSV export
  --format FORMAT    Output format (default is CSV)
~~~~

## Example

~~~~bash
adulau@kolmogorov ~/git/hashlookup-forensic-analyser/bin $ python3 hashlookup-analyser.py --print-all -d /usr/local/bin/ --include-stats
unknown,/usr/local/bin/octopress
unknown,/usr/local/bin/safe_yaml
unknown,/usr/local/bin/bayes.rb
unknown,/usr/local/bin/redcarpet
unknown,/usr/local/bin/listen
unknown,/usr/local/bin/f2py
unknown,/usr/local/bin/f2py3.8
unknown,/usr/local/bin/tabulate
unknown,/usr/local/bin/jekyll
unknown,/usr/local/bin/pdf2txt.py
unknown,/usr/local/bin/rougify
unknown,/usr/local/bin/summarize.rb
unknown,/usr/local/bin/camelot
unknown,/usr/local/bin/kramdown
unknown,/usr/local/bin/posix-spawn-benchmark
unknown,/usr/local/bin/f2py3
unknown,/usr/local/bin/__pycache__/dumppdf.cpython-38.pyc
unknown,/usr/local/bin/__pycache__/pdf2txt.cpython-38.pyc
known,/usr/local/bin/scss
known,/usr/local/bin/sass-convert
known,/usr/local/bin/dumppdf.py
known,/usr/local/bin/sass
stats,Analysed directory /usr/local/bin/ on kolmogorov running Linux-5.10.0-1045-oem-x86_64-with-glibc2.29 at 2021-10-03 10:09:18.254424+00:00- Found 4 on hashlookup.circl.lu - Unknown files 18 - Excluded files 0
~~~~

# License

The software is open source software released under the "Simplified BSD License".

Copyright 2021 Alexandre Dulaunoy

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

