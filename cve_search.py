#!/usr/bin/python

import json
import time
import sys, getopt, os, glob
from datetime import datetime, timedelta


cve_dir = "/home/bartosz/CVEs/"
full_cve_filedirectory = "/home/bartosz/Downloads/circl-cve-search-expanded.json"


def main(argv):
    param_date = datetime.strptime("1970", '%Y')
    param_cve_score = 0
    param_vuln_name = ""
    RESULTS = []

    # Console argument processing
    try:
        opts, args = getopt.getopt(argv,"hy:c:n:",["year=","cvss=","name="])
    except getopt.GetoptError:
        print('cve_search.py -y <publication_year> -c <CVSS_score> -n <vuln_name>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('cve_search.py -y <publication_year> -c <CVSS_score> -n <vuln_name>')
            sys.exit()
        elif opt in ("-y", "--year"):
            param_date = datetime.strptime(arg, '%Y')
        elif opt in ("-c", "--cvss"):
            param_cve_score = float(arg)
        elif opt in ("-n", "--name"):
            param_vuln_name = str(arg)


        #TODO: add "impact": {"availability": "COMPLETE", "confidentiality": "COMPLETE", "integrity": "COMPLETE"}
        #TODO: add "access":{"authentication":"NONE", "complexity":"MEDIUM","vector":"NETWORK"}

    runtime = time.time()
#  Open each file in directory.
    for json_file in [x for x in glob.glob("*.json")]:
        start = time.time()
        with open(cve_dir + json_file, 'r') as f:
            print("Processing file: {}".format(json_file))
            data = f.read()
            # print("Read time: " + str(time.time() - start))

            start = time.time()
            obj = json.loads(data)
            # print("Parse time: " + str(time.time() - start))

            elem_index = 0
            for elem in obj["results"]:
                # if true -> add current element to results
                add = False

                # Search for records published after $param_date
                date = datetime.strptime(elem["Published"], '%Y-%m-%d %H:%M:%S')
                # print("\n#{}\t{}".format(str(elem_index), str(date)))
                # if (date > param_date):
                #     add = True
                #     # print("\tPublished: " + str(date))

                # # Find records with CVE score higher than $param_cve_score
                # if (elem['cvss'] >= param_cve_score):
                #     add = True
                #     # print("\tCVSS: " +str(elem['cvss']))
                
                # Find records with matching vulnerability name $param_vuln_name
                #TODO: this is in 'capec' element (Common Attack Pattern Enumeration and Classification)

                print(elem['capec']['name'])
                if('capec' in elem and param_vuln_name in elem['capec']['name']):
                    print("CVE name: {}".format(elem['name']))
                    add = True
                    print("\tVuln name: '{}' found in '{}' ",format(param_vuln_name, elem['name']))

            # If any of the search conditions is satisfied, add to RESULTS array
                if (add):
                    RESULTS.append(elem)
                    # print("\tElement #{} added to results.".format(elem_index))
                elem_index = elem_index +1

        print("\nRESULTS = {}".format(len(RESULTS)))
    print("Run time: " + str(time.time() - runtime))

if __name__ == "__main__":
   main(sys.argv[1:])