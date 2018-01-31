import urllib.request
import zipfile
import argparse
import sys

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


vul_xmlzip_url = "https://bdu.fstec.ru/documents/files/vulxml.zip"
vul_xmlzip_file = "vulxml.zip"
vul_xml_file = "export/export.xml"

def get_bdu ():
    try:
        urllib.request.urlretrieve(vul_xmlzip_url, vul_xmlzip_file)
    except:
        print ("Can't download file!")
        exit (666)

    zip_ref = zipfile.ZipFile(vul_xmlzip_file, 'r')
    zip_ref.extractall(".")
    zip_ref.close()

def search_bdu(cve):
    root = ET.parse(vul_xml_file).getroot()
    #print (root.tag)

#Find BDU + CVE
#    for i in root.findall(".//identifier[@type='CVE']/../.."):
#        print (i.tag)
#        print ("".join(i.find("identifier").itertext()))
#        print ("".join(i.find(".//identifier[@type='CVE']").itertext()))

    for i in root.findall(".//identifiers[identifier='"+cve+"']/.."):
        #print (i.tag)
        print ("BDU:"+"".join(i.find("identifier").itertext()))
        print ("".join(i.find("name").itertext()))
        #print ("".join(i.find(".//identifier[@type='CVE']").itertext()))

def parse_openvas_xml (xml_file):
    root = ET.parse(xml_file).getroot()
    for i in root.findall(".//cve"):
        cve = "".join(i.itertext())
        if cve != "NOCVE":
            for j in cve.split(", "):
                print ("CVE:"+j)
                search_bdu(j)
                print ("="*30)



# MAIN

parser = argparse.ArgumentParser(description='OpenVAS XML CSV --> BDU')
parser.add_argument('-i', dest="xml_file", help="OpenVAS XML", required=True)
try:
    results = parser.parse_args()
except:
    parser.print_help()
    sys.exit(0)
print(results)
#get_bdu()
#search_bdu("CVE-2014-1568")
parse_openvas_xml (results.xml_file)
