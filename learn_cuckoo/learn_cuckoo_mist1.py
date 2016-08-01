#!/bin/python

import gzip
import ujson
import os
import sys
import xml.etree.ElementTree as ET


def run_parser(folder):
    learn_reports = {}

    i = 0
    for top, dirs, files in os.walk(folder):

        for nm in files:
            report = os.path.join(top, nm)
            i += 1
            if i % 1 == 0:
                print("Processing report number %i" % i)

            if report.endswith(".gz"):
                with gzip.GzipFile(report, 'r') as fp:
                    jo = ujson.load(fp)
            else:
                with open(report, 'r') as fp:
                    jo = ujson.load(fp)

            procs = jo['behavior']['processes']
            for proc in procs:
                calls = proc['calls']
                for call in calls:
                    try:
                        learn_reports[call['category']].add(call['api'])
                    except:
                        learn_reports[call['category']] = set()
                        learn_reports[call['category']].add(call['api'])

    root = ET.Element("elements2mist")
    tree = ET.ElementTree(root)
    report_id = 1
    for category, apis in learn_reports.items():
        e = ET.Element(category)
        e.set("mist", "{0:02x}".format(report_id))
        report_id += 1
        root.append(e)

        api_id = 1
        for api in apis:
            a = ET.Element(api)
            a.set("mist", "{0:02x}".format(api_id))
            e.append(a)
            api_id += 1

    return tree


def main():
    try:
        input_dir = sys.argv[1]
        if os.path.exists(input_dir):
            tree = run_parser(input_dir)
            tree.write(sys.argv[2])
        else:
            print("Folder provided does not exists ")
            sys.exit()
    except:
        raise


if __name__ == '__main__':
    main()
