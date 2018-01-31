import urllib.request
import zipfile
try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


vul_xmlzip_url = "https://bdu.fstec.ru/documents/files/vulxml.zip"
vul_xmlzip_file = "vulxml.zip"
vul_xml_file = "export/export.xml"

def get_bdu ():
    urllib.request.urlretrieve(vul_xmlzip_url, vul_xmlzip_file)

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
        print (i.tag)
        print ("".join(i.find("identifier").itertext()))
        print ("".join(i.find("name").itertext()))
        print ("".join(i.find(".//identifier[@type='CVE']").itertext()))




#get_bdu()
search_bdu("CVE-2014-1568")