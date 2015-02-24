# nessus_join
Join multiple Nessus reports into one

```
Usage: nessjoin.py [options]

Options:
  -h, --help            show this help message and exit
  -d DIR, --dir=DIR     Directory containing .nessus files
  -o OUTPUT, --output=OUTPUT
                        output file name
  -n NAME, --name=NAME  New report name
  -v, --verbose         Show extra information
```

Example:

```
python nessjoin.py -d scans/ -n 'ACME Network Scan' -o scan_2015.nessus
```
