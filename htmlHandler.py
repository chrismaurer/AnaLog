import os
import subprocess
from Timestamp import getDateStamp

log_results_dir = r'\\10.31.60.183\c$\AnaLog'
index_html = log_results_dir + '\\' + 'index.html'
today_file = log_results_dir + '\\' + getDateStamp() + '_Logfiles.html'
hyperlink_path = r'file://///10.31.60.183/AnaLog/'

def catalog_by_date():
    """Login to the AnaLog Web Server"""
    netusecmd = r'net use \\10.31.60.183\c$ /user:10.31.60.183\Administrator 12345678'
    login_response = subprocess.Popen(netusecmd, stdout=subprocess.PIPE).communicate()
    if 'The command completed successfully' not in str(login_response):
        return False
    else:
        if not os.path.exists(today_file):
            indexfile = file(index_html, 'a')
            indexfile.write('\n<h3><a href=\"' + getDateStamp() + '_Logfiles.html\">' + getDateStamp() + '</a></h3>\n')
            indexfile.close()

            datefile = file(today_file, 'a')
            datefile.write('<title>AnaLog Results from ' + getDateStamp() + '</title>\n')
            datefile.write('<html>\n<head></head>\n<body>\n')
            datefile.write('<center><img src=TT_horizontal_2lines_4c_logo.png></center>\n')
            datefile.write('<h1 style="font-family: Arial; text-align:center; color: white; background-color: #0099CC;">AnaLog Results from ' + getDateStamp() + '</h1>\n')
            datefile.write('<p style="font-family: Arial; text-align:center;"><a href="http://10.31.60.183/">[BACK]</a></p>\n')
            datefile.close()

    return today_file