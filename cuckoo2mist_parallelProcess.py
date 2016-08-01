import os
import sys
from multiprocessing import pool as processPool

from cuckoo2mist import class_mist

config = "./conf"

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i+n]

def process(reports):
    global config
    elements2mist, types2mist = class_mist.read_configuration(config)

    for report in reports:
        x = class_mist.mistit(report, elements2mist, types2mist)
        if x.parse() and x.convert():
            x.write(report.replace("json.gz", "mist"))





def main(folder):
    reports = []
    for top, dirs, files in os.walk(folder):
        for nm in files:
            report = os.path.join(top, nm)
            reports.append(report)

    pool = processPool.Pool()
    reports_separated = chunks(reports, 100)
    pool.map(process, reports_separated)

if __name__ == "__main__":
    main(sys.argv[2])