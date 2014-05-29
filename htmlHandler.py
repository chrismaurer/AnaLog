import os
import time
import logging
import shutil
import zipfile
import subprocess
import getpass
import re
from gwInfoLookup import gwInfoLookup 
from LogFileUtils import isMessageInLogFile
from logExceptions import logExceptions
from Timestamp import getTimeStamp, getDateStamp, getSecSinceEpoch

log = logging.getLogger(__name__)

log_results_dir = r'\\10.31.56.8\c$\AnaLog'
index_html = log_results_dir + '\\' + 'index.html'
today_file = log_results_dir + '\\' + getDateStamp() + '_Logfiles.html'
hyperlink_path = r'file://///10.31.56.8/c$/AnaLog/'

def catalog_by_date():
    if not os.path.exists(today_file):
        indexfile = file(index_html, 'a')
        indexfile.write('\n<h3><a href=\"' + getDateStamp() + '_Logfiles.html\">' + getDateStamp() + '</a></h3>\n')
        indexfile.close()

        datefile = file(today_file, 'a')
        datefile.write('<title>AnaLog Results from ' + getDateStamp() + '</title>\n')
        datefile.write('<html>\n<head></head>\n<body>\n')
        datefile.write('<center><img src=TT_horizontal_2lines_4c_logo.png></center>\n')
        datefile.write('<h1 style="font-family: Arial; text-align:center; color: white; background-color: #0099CC;">AnaLog Results from ' + getDateStamp() + '</h1>\n')
        datefile.write('<p style="font-family: Arial; text-align:center;"><a href="http://10.31.56.8:8080/">[BACK]</a></p>\n')
        datefile.close()

    return today_file