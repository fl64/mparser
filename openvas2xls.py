import sqlite3
import xlsxwriter
import argparse
import sys
from sqlite3 import Error

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET

#NOT USED!
sql_report_table = """ CREATE TABLE IF NOT EXISTS report (
     id integer PRIMARY KEY,
     r_name text NOT NULL
     r_scan_date text NOT NULL  );
"""


sql_threats_table = """ CREATE TABLE IF NOT EXISTS threats (
     id integer PRIMARY KEY,
     t_name text NOT NULL  );
"""

sql_assets_table = """ CREATE TABLE IF NOT EXISTS assets (
     id integer PRIMARY KEY,
     asset_id text NOT NULL,
     hostname text NOT NULL,
     ip text NOT NULL,
     OS text NOT NULL  );
"""

sql_results_table = """ CREATE TABLE IF NOT EXISTS results (
     id integer PRIMARY KEY,
     vuln_name text NOT NULL,
     asset_id text NOT NULL,
     port text,
     threat text,
     severity text,
     family text,
     app_name text,
     app_location text,
     app_src text,
     bid text,
     cve text

     );
"""

try:
    from xml.etree import cElementTree as ET
except ImportError:
    from xml.etree import ElementTree as ET


def create_connection(db_file):
    try:
        conn = sqlite3.connect(db_file)
        print("Created connection for SQLite v" + sqlite3.version)
        return conn
    except Error as e:
        print(e)

    return None


def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def parse_openvas_report(conn,xml_file):
    root = ET.parse(xml_file).getroot()
    # get all hosts in report

    #fill threat table
    threat = ("High", "Medium", "Low")
    for t in threat:
        insert_result_data = 'INSERT INTO threats ( t_name ) VALUES ( "'+t+'" )'
        try:
            c = conn.cursor()
            c.execute(insert_result_data,)
        except Error as e:
            print(e)


    #fill host table
    for host in root.findall("./report/host"):
        ip = "".join(host.find("./ip").itertext())
        asset_id = host.find("./asset").get('asset_id')

        hostname = ip
        OS = "unknown"
        for host_detail in host.findall("./detail"):
            host_detail_name = "".join(host_detail.find("./name").itertext())

            if host_detail_name == "best_os_txt":
                OS = "".join(host_detail.find("./value").itertext())
            elif host_detail_name == "hostname":
                hostname = "".join(host_detail.find("./value").itertext())
        insert_asset_data = 'INSERT INTO assets (asset_id, hostname, ip, OS) VALUES (?, ?, ?, ?)'
        asset = (asset_id, hostname, ip, OS)
        try:
            c = conn.cursor()
            c.execute(insert_asset_data, asset)
        except Error as e:
            print(e)

    # get all vulnerabilities
    for res in root.findall("./report/results/result"):
        vuln_name = "".join(res.find("./name").itertext())
        asset_id = res.find("./host/asset").get('asset_id')
        port = "".join(res.find("./port").itertext())
        threat = "".join(res.find("./threat").itertext())
        if threat.lower() == "high": threat = 1
        elif threat.lower() == "medium": threat = 2
        elif threat.lower() == "low": threat = 3
        else : threat = 0

        app_name = " - "
        app_src = " - "
        app_location = " - "
        cve = " - "
        bid = " - "
        severity = "".join(res.find("./severity").itertext())
        family = "".join(res.find("./nvt/family").itertext())
        cve = "".join(res.find("./nvt/cve").itertext())
        bid = "".join(res.find("./nvt/bid").itertext())
        for details in res.findall(".//details/detail"):
            detail_name = "".join(details.find("./name").itertext())
            if detail_name == "product":
                app_name = "".join(details.find("./value").itertext())
            elif detail_name == "source_name":
                app_src = "".join(details.find("./value").itertext())
            elif detail_name == "location":
                app_location = "".join(details.find("./value").itertext())

        insert_result_data = 'INSERT INTO results ( vuln_name, asset_id, port, threat, severity, family, app_name, app_src, app_location, bid, cve) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'

        result = (vuln_name, asset_id, port, threat, severity, family, app_name, app_src, app_location, bid, cve)
        try:
            c = conn.cursor()
            c.execute(insert_result_data, result)
        except Error as e:
            print(e)


def sql_query(conn, sql):
    try:
        c = conn.cursor()
        c.execute(sql)
        return c
    except Error as e:
        print(e)


def create_xls(conn,xlsx_file):
    chart_width = 520  # 7 Cells
    chart_height = 240
    chart_height_cell = 14
    padding = 2

    workbook = xlsxwriter.Workbook(xlsx_file)
    format_report_title = workbook.add_format({'bold': True, 'size': 16, 'align': 'center'})
    format_report_title_hi = workbook.add_format({'bold': True, 'size': 12})
    format_report_title_med = workbook.add_format({'bold': True, 'size': 12})
    format_report_title_low = workbook.add_format({'bold': True, 'size': 12})

    format_table_title_hi = workbook.add_format({'bold': True, 'size': 10, 'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1, 'bg_color': "#ef2929" })
    format_table_title_med = workbook.add_format({'bold': True, 'size': 10, 'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1, 'bg_color': "#f57900"})
    format_table_title_low = workbook.add_format({'bold': True, 'size': 10, 'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1, 'bg_color': "#fce94f"})
    format_table_title = workbook.add_format({'bold': True, 'size': 10, 'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1})

    format_table_cell = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1, 'size': 9})

    format_text = workbook.add_format({'border': 0, 'align': 'justify', 'valign': 'vcenter', 'text_wrap': 1, 'size': 9})

    format_table_cell_hi = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1, 'size': 9, 'bg_color': "#ef2929"})
    format_table_cell_med = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1, 'size': 9, 'bg_color': "#f57900"})
    format_table_cell_low = workbook.add_format({'border': 1, 'align': 'center', 'valign': 'vcenter', 'text_wrap': 1, 'size': 9, 'bg_color': "#fce94f"})

    # Get translation object
    # trans = loader(get_translation_path("excel", lang))
    # sheet_name = trans["summary"]

    sheet_name = "Отчет"
    ws = workbook.add_worksheet(sheet_name)
    ws.set_column("A:A", 1)
    ws.set_column("B:D", 18)
    ws.set_column("E:H", 4)
    ws.set_column("I:I", 1)
    ws.set_default_row(14)

    # ==================================================================================================================
    # HEADER
    # ==================================================================================================================

    hosts_count = sql_query(conn, 'SELECT count(*) FROM assets').fetchone()[0]
    vulns_count = sql_query(conn, 'SELECT count(*) FROM results').fetchone()[0]

    ws.merge_range("B2:H2", "Отчет по результатам инструментального сканирования", format_report_title)
    ws.set_row(1, 30)
    global_index = 6  # start Position


    index = start_index = 4  # 1 - Table name + 1 Table header
    ws.merge_range("B" + str(global_index + index - 4) + ":H" + str(global_index + index - 4), """При проведении инструментального сканирования с использованием сканера уязвимостей было обнаружено {} сетевых узлов, на которых выявлено {} уязвимостей.  
    Обнаруженные уявзвимости имеют разную критичность и условно разделяются на следующие категории:
    - Уязвимости высокой степени критичности (High);
    - Уязвимости средней степени критичности (Med);
    - Уязвимости низкосй степени критичности (Low).
    В таблице (Таблица 1) представлена информация по количеству обнаруженных уявзвимостей для каждой категории.
    """.format(hosts_count, vulns_count), format_text)
    ws.set_row(global_index + index - 5, 120)


    # ===================================================================================================================
    # ===================================================================================================================
    # ===================================================================================================================
    # ===================================================================================================================

    sql = 'SELECT t.t_name, count(*) FROM results AS r LEFT JOIN threats AS t ON t.id = r.threat GROUP BY r.threat '
    ws.set_row(global_index + start_index - 2, 30)
    ws.write("B" + str(global_index + start_index - 2), "Таблица 1. Статистика по обнаруженным уявзвимостям")
    ws.write("B" + str(global_index + start_index - 1), "Критичность", format_table_title)
    ws.write("C" + str(global_index + start_index - 1), "Число найденных уявзвимостей", format_table_title)
    for row in sql_query(conn, sql):
        ws.write("B" + str(global_index + index), row[0], format_table_cell)
        ws.write("C" + str(global_index + index), row[1], format_table_cell)
        print(row)
        index += 1

    chart = workbook.add_chart({'type': 'column'})
    chart.add_series({
        'name': 'Число найденных уязвимостей по уровням критичности',
        'categories': '=%s!B%s:B%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
        'values': '=%s!C%s:C%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
    })

    chart.set_title({'name': 'Уязвимости по уровням критичности'})
    # chart_vulns_summary.set_style(35)
    #chart.set_title({'font': {'size': 4, 'bold': 1}})
    chart.set_title({'none': True})
    chart.set_legend({'none': True})
    chart.set_size({'width': chart_width, 'height': chart_height})
    ws.insert_chart("B" + str(global_index + index + 1), chart)

    print("globalindex:",global_index,"index: ",index)

    global_index = global_index + index + chart_height_cell + padding
    # ===================================================================================================================
    # ===================================================================================================================
    # ===================================================================================================================




    index = start_index = 4  # 1 - Table name + 1 Table header

    ws.merge_range("B" + str(global_index + index - 4) + ":H" + str(global_index + index - 4), """В таблице (Таблица 2) представлена информация о числе просканированных сетевых узлова на которых были обнаружены уязвимости различных категорий критичности""", format_text)
    ws.set_row(global_index + index - 5, 30)

    sql = 'SELECT  t.t_name, count(DISTINCT r.asset_id) FROM results AS r LEFT JOIN threats AS t ON t.id = r.threat GROUP BY r.threat;'
    ws.set_row(global_index + start_index - 2, 30)
    ws.write("B" + str(global_index + start_index - 2), "Таблица 2. Распределению уязвимостей по сетевым узлам")
    ws.write("B" + str(global_index + start_index - 1), "Критичность", format_table_title)
    ws.write("C" + str(global_index + start_index - 1), "Число сетевых узлов", format_table_title)
    for row in sql_query(conn, sql):
        ws.write("B" + str(global_index + index), row[0], format_table_cell)
        ws.write("C" + str(global_index + index), row[1], format_table_cell)
        print(row)
        index += 1

    chart = workbook.add_chart({'type': 'column'})
    chart.add_series({
        'name': 'Число сетевых узлов с уязвимостями',
        'categories': '=%s!B%s:B%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
        'values': '=%s!C%s:C%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
    })

    chart.set_title({'name': 'Число сетевых узлов с уязвимостями'})
    # chart.set_style(35)
    chart.set_title({'none': True})
    chart.set_legend({'none': True})
    chart.set_size({'width': chart_width, 'height': chart_height})
    ws.insert_chart("B" + str(global_index + index + 1), chart)

    print("globalindex:",global_index,"index: ",index)


    global_index = global_index + index + chart_height_cell + padding
    # ===================================================================================================================
    # ===================================================================================================================
    # ===================================================================================================================
    index = start_index = 4  # 1 - Table name + 1 Table header

    ws.merge_range("B" + str(global_index + index - 4) + ":H" + str(global_index + index - 4), """Информация по обнаруженным в процессе сканирования ОС на сетевых узлах представлена в таблице (Таблица 3).""", format_text)
    ws.set_row(global_index + index - 5, 30)


    sql = 'SELECT  a.OS, count(*) FROM assets AS a GROUP BY a.OS;'
    ws.set_row(global_index + start_index - 2, 30)
    ws.write("B" + str(global_index + start_index - 2), "Таблица 3. Обнаруженные ОС")
    ws.write("B" + str(global_index + start_index - 1), "ОС", format_table_title)
    ws.write("C" + str(global_index + start_index - 1), "Число сетевых узлов", format_table_title)
    for row in sql_query(conn, sql):
        ws.set_row(global_index + index - 1, 30)
        ws.write("B" + str(global_index + index), row[0], format_table_cell)
        ws.write("C" + str(global_index + index), row[1], format_table_cell)
        print(row)
        index += 1

    chart = workbook.add_chart({'type': 'pie'})
    chart.add_series({
        'name': 'Обнаруженные ОС',
        'categories': '=%s!B%s:B%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
        'values': '=%s!C%s:C%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
    })

    chart.set_title({'name': 'Обнаруженные ОС'})
    # chart.set_style(35)
    chart.set_title({'none': True})
    # chart.set_legend({'none': True})
    chart.set_size({'width': chart_width, 'height': chart_height})
    ws.insert_chart("B" + str(global_index + index + 1), chart)

    print("globalindex:",global_index,"index: ",index)

    global_index = global_index + index + chart_height_cell + padding

    # ===================================================================================================================
    # ===================================================================================================================
    # ===================================================================================================================
    index = start_index = 4  # 1 - Table name + 1 Table header

    ws.merge_range("B" + str(global_index + index - 4) + ":H" + str(global_index + index - 4), """В таблице (Таблица 4) представлен перечень портов, на которых функционируют уязвимые сервисы, и количество сетевых узлов на котором эти порты доступны.
    """, format_text)
    ws.set_row(global_index + index - 5, 30)

    sql = 'SELECT  r.port, count(DISTINCT r.asset_id) FROM results AS r GROUP BY r.port;'
    ws.set_row(global_index + start_index - 2, 30)
    ws.write("B" + str(global_index + start_index - 2), "Таблица 4. Число портов уязвимых сервисов")
    ws.write("B" + str(global_index + start_index - 1), "Порт", format_table_title)
    ws.write("C" + str(global_index + start_index - 1), "Число сетевых узлов", format_table_title)
    for row in sql_query(conn, sql):
        ws.write("B" + str(global_index + index), row[0], format_table_cell)
        ws.write("C" + str(global_index + index), row[1], format_table_cell)
        print(row)
        index += 1

    chart = workbook.add_chart({'type': 'column'})
    chart.add_series({
        'name': 'Обнаруженные порты',
        'categories': '=%s!B%s:B%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
        'values': '=%s!C%s:C%s' % (sheet_name, str(global_index + start_index), str(global_index + index - 1)),
    })

    chart.set_title({'name': 'Обнаруженные порты'})
    # chart.set_style(35)
    chart.set_title({'none': True})
    chart.set_legend({'none': True})
    chart.set_size({'width': chart_width, 'height': chart_height})
    ws.insert_chart("B" + str(global_index + index + 1), chart)

    print("globalindex:",global_index,"index: ",index)

    global_index = global_index + index + chart_height_cell + padding


    # ===================================================================================================================
    # ===================================================================================================================
    # ===================================================================================================================
    index = start_index = 4  # 1 - Table name + 1 Table header

    ws.merge_range("B" + str(global_index + index - 4) + ":H" + str(global_index + index - 4), """В таблице (Таблица 5) представлена информация по всем просканированным сетевым узлам и информация по обнаруженным на них уявзвимостям.""", format_text)
    ws.set_row(global_index + index - 5, 30)

    sql = '''
    SELECT  a.hostname, a.ip, a.os, 
    (SELECT count(*) FROM results AS r1 WHERE r1.asset_id=a.asset_id and r1.threat=1) as high,
    (SELECT count(*) FROM results AS r2 WHERE r2.asset_id=a.asset_id and r2.threat=2) as medium,
    (SELECT count(*) FROM results AS r3 WHERE r3.asset_id=a.asset_id and r3.threat=3) as low,
    (SELECT count(*) FROM results AS r3 WHERE r3.asset_id=a.asset_id) as total
    FROM assets AS a;
    '''
    ws.set_row(global_index + start_index - 2, 30)
    ws.write("B" + str(global_index + start_index - 2), "Таблица 5. Обнаруженные сетевые узлы")
    ws.write("B" + str(global_index + start_index - 1), "Имя узла", format_table_title)
    ws.write("C" + str(global_index + start_index - 1), "IP-адрес узла", format_table_title)
    ws.write("D" + str(global_index + start_index - 1), "ОС", format_table_title)
    ws.write("E" + str(global_index + start_index - 1), "High", format_table_title_hi)
    ws.write("F" + str(global_index + start_index - 1), "Med", format_table_title_med)
    ws.write("G" + str(global_index + start_index - 1), "Low", format_table_title_low)
    ws.write("H" + str(global_index + start_index - 1), "Всего", format_table_title)
    for row in sql_query(conn, sql):
        ws.set_row(global_index + index - 1, 30)
        ws.write("B" + str(global_index + index), row[0], format_table_cell)
        ws.write("C" + str(global_index + index), row[1], format_table_cell)
        ws.write("D" + str(global_index + index), row[2], format_table_cell)
        ws.write("E" + str(global_index + index), row[3], format_table_cell)
        ws.write("F" + str(global_index + index), row[4], format_table_cell)
        ws.write("G" + str(global_index + index), row[5], format_table_cell)
        ws.write("H" + str(global_index + index), row[6], format_table_cell)
        print(row)
        index += 1

    global_index = global_index + index + chart_height_cell + padding

    print("globalindex:",global_index,"index: ",index)

    sql = 'SELECT  count(*), r.vuln_name, r.family, r.port, a.hostname, a.IP, a.OS, r.threat, r.severity, r.app_name FROM results AS r LEFT JOIN assets AS a ON r.asset_id = a.asset_id GROUP BY r.family, r.app_name'
    # for row in sql_query(conn, sql):
    #   print(row)
    workbook.close()




parser = argparse.ArgumentParser(description='OpenVAS XML to XLSX convertor')
parser.add_argument('-i', dest="xml_file", help="Путь к файлу отчета OpenVAS", metavar='in-file', required=True )
parser.add_argument('-o', dest="xlsx_file", help="Путь к файлу XLSX для сохранения отчета", metavar='out-file', required=True)
try:
    results = parser.parse_args()

except:
    parser.print_help()
    sys.exit(0)
print(results)

conn = create_connection(':memory:')
create_table(conn, sql_assets_table)
create_table(conn, sql_results_table)
create_table(conn, sql_threats_table)
parse_openvas_report(conn, results.xml_file)
create_xls(conn, results.xlsx_file)