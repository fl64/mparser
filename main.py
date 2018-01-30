import sqlite3
import xlsxwriter
import argparse
import sys
from sqlite3 import Error

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


def parse_mp8_report(xml_file):
    ns = "http://www.ptsecurity.ru/reports" #namespace = xmlns

    root = ET.parse(xml_file).getroot()

    for vln in root.findall("./{%s}vulners/{%s}vulner" %(ns, ns)):
        #print (vln.tag)
        print (vln.get("id"))
        print ( "".join(vln.find("./{%s}title" %(ns)).itertext()))# get text between tags
        for vlnid in vln.findall("./{%s}global_id" %(ns)):
            print (vlnid.get("name")+"  "+vlnid.get("value"))



parser = argparse.ArgumentParser(description='MP8 XML')
parser.add_argument('-i', dest="xml_file", help="Путь к файлу отчета MP8", required=True )

try:
    results = parser.parse_args()

except:
    parser.print_help()
    sys.exit(0)
print(results)

parse_mp8_report(results.xml_file)
