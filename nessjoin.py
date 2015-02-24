#!/usr/bin/env python
'''

Name: nessjoin.py
Description: Combine multiple Nessus scans into one.
Version: 0.1
Author: Roy Firestein
Date: Feb 4 2013

'''

import os
import xml.dom.minidom
from optparse import OptionParser


parser = OptionParser()
parser.add_option("-d", "--dir", action="store", type="string", dest="dir", help="Directory containing .nessus files")
parser.add_option("-o", "--output", action="store", type="string", dest="output", help="output file name")
parser.add_option("-n", "--name", action="store", type="string", default="combined scan", dest="name",
                  help="New report name")
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="Show extra information")
(menu, args) = parser.parse_args()


def parse_targets(domxml, set_value=None):
    pref = domxml.getElementsByTagName('ServerPreferences')[0]
    for p in pref.childNodes:
        for c in p.childNodes:
            if c.nodeType == c.ELEMENT_NODE and c.childNodes[0].data == 'TARGET':
                if set_value:
                    c.nextSibling.nextSibling.childNodes[0].data = set_value
                    return domxml
                else:
                    return c.nextSibling.nextSibling.childNodes[0].data.split(",")


def main():
    if menu.dir and menu.output:
        files = []
        dir_nessus = os.path.realpath(menu.dir)
        nessus_files = os.listdir(dir_nessus)
        scan_result = []
        targets = []
        counter = 0

        for nes_file in nessus_files:
            if '.nessus' in nes_file:
                files.append(os.path.join(dir_nessus, nes_file))

        for nes_file in files:
            nessus_xml = open(nes_file, 'r').read()
            if counter == 0:
                # first Nessus scan
                first_dom = xml.dom.minidom.parseString(nessus_xml)

                # Save report scope
                targets = parse_targets(first_dom)

                if menu.name:
                    first_dom.getElementsByTagName('Report')[0].setAttribute('name', menu.name)
            else:
                try:
                    dom = xml.dom.minidom.parseString(nessus_xml)
                    test = dom.getElementsByTagName('ReportHost')
                except:
                    # if no element "ReportHost", skip this
                    print "Could not parse %s" % nes_file
                    continue
                for host in dom.getElementsByTagName('ReportHost'):
                    scan_result.append(host)
                # Save targets
                target = parse_targets(dom)
                for t in target:
                    if t not in targets:
                        targets.append(t)
                    else:
                        print "Duplicate range (%s) found in %s" % (t, nes_file)
            counter += 1

        for node in scan_result:
            first_dom.getElementsByTagName('Report')[0].appendChild(node)

        # Update TARGETS preferences
        first_dom = parse_targets(first_dom, set_value=",".join(targets))

        # Save new combined report
        fh = open(menu.output, 'w')
        fh.write(first_dom.toxml(encoding="utf-8"))
        fh.close()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()