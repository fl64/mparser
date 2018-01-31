import argparse
import sys

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


def parse_mp8_report(xml_file):
    ns = "http://www.ptsecurity.ru/reports" #namespace = xmlns

    root = ET.parse(xml_file).getroot()





    for vln in root.findall("./{%s}vulners/{%s}vulner" %(ns, ns)): # <content><vulners><vulner>...
        #print (vln.tag)
        print (vln.get("id"))
        print ( "".join(vln.find("./{%s}title" %(ns)).itertext()))# get text between tags
        for vlnid in vln.findall("./{%s}global_id" %(ns)): # <content><vulners><vulner><global_id>...
            print (vlnid.get("name")+"  "+vlnid.get("value"))

    for host in root.findall("./{%s}data/{%s}host" %(ns, ns)):
        print(host.get("ip"))



parser = argparse.ArgumentParser(description='MP8 XML')
parser.add_argument('-i', dest="xml_file", help="MP8 XML Path", required=True )

try:
    results = parser.parse_args()

except:
    parser.print_help()
    sys.exit(0)
print(results)

parse_mp8_report(results.xml_file)
