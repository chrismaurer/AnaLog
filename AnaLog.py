# ~TT Gateway Logfile Analyser

# ~This script extracts TT Logfile Zips and analyses them, removing all "background noise" from the files.
# ~The meaningful error messages are compiled into a report and posted to the AnaLog web server.

__author__ = 'Chris Maurer (chris.maurer@tradingtechnologies.com)'
__version__ = '2.2'

import os
import time
import logging
import shutil
import zipfile
import getpass
import re
import smtplib
from gwInfoLookup import gwInfoLookup
from logExceptions import logexceptions
from Timestamp import getTimeStamp, getDateStamp, getSecSinceEpoch
from htmlHandler import catalog_by_date

log = logging.getLogger(__name__)

class AnaLog():
    def __init__(self):
        self.all_errors_list = []
        self.severity_summary = []
        self.minidump_files = []
        self.zip_list = []
        self.log_list = []
        self.gw_flavour = None
        self.gw_ip = None
        self.gw_version = None
        self.pfx_enabled = None
        self.token_enabled = None
        self.cwd = r'C:\temp\logs'
        self.tempdir = self.cwd + '\\tmp'
        self.logdir = self.tempdir + '\\tt\logfiles'
        self.inst_logdir = self.logdir + '\\install'
        self.configdir = self.tempdir + '\\tt\config'
        self.source_log_path = r'C:\temp\logtemp'
        self.destdir = None
        self.archivedir = r'\\10.31.60.183\c$\log_archives' + '\\' + 'archive_' + getDateStamp() + '_' + getTimeStamp()
        self.log_results_dir = r'\\10.31.60.183\c$\AnaLog'
        self.hyperlink_path = r'file://///10.31.60.183/log_archives/archive_' + \
                              getDateStamp() + '_' + getTimeStamp() + '/'
        self.today_file = catalog_by_date()

    def setup_class(self):
        """Create local directories of they don't already exist"""
        if not os.path.exists(r'c:\temp'):
            os.mkdir(r'c:\temp')
        if not os.path.exists(self.cwd):
            os.mkdir(self.cwd)
        if not os.path.exists(self.source_log_path):
            os.mkdir(self.source_log_path)

    def grab_original_zip_files(self):
        """Get path to the original ZIP files and copy them to local PC"""
        filename = r'C:\temp\AnaLog.ini'

        while True:
            if os.path.exists(filename):
                f = file(filename, 'r')
                hist = f.readline()
                f.close()
            else:
                hist = None
            get_zip_file_path = raw_input('Please enter the path of the Zip files to analise [%s] : ' % hist)
            if len(get_zip_file_path) > 0:
                f = file(filename, 'w')
                f.write(get_zip_file_path)
                f.close()
            original_zipfile_path = hist if len(get_zip_file_path) == 0 else get_zip_file_path
            if original_zipfile_path is None:
                print 'ERROR! Could not locate Original Zip Files!'
                raw_input('Press ENTER to re-try.')
            else:
                print 'Copying Zip files from %s...' % original_zipfile_path
                for zipFile in os.listdir(original_zipfile_path):
                    if '.zip' in zipFile:
                        shutil.copy(original_zipfile_path + '\\' + zipFile, self.source_log_path)
                break

    def get_log_zips(self):
        """Check logfiles' source directory and get a list and count of zips to work from"""
        for fileName in os.listdir(self.source_log_path):
            if '.zip' in fileName:
                self.zip_list.append(fileName)
        zipfile_count = len(self.zip_list)
        if zipfile_count == 0:
            print 'ERROR! There are no logfile ZIPs in the specified directory!'
        return zipfile_count

    def list_of_zips(self):
        """Pass file name of current logfile zip to be extracted."""
        for zipFileName in self.zip_list:
            zip_file = self.source_log_path + '\\' + zipFileName
            yield zip_file

    def log_unzip(self, current_zipfile):
        """Decompress the zip files"""
        z = zipfile.ZipFile(current_zipfile)
        for folderName in os.listdir(self.cwd):
            if folderName == 'tmp':
                print 'An old temp folder was found and is therefore being removed.'
                shutil.rmtree(self.cwd + '\\' + folderName)
        print 'Extracting Zip: %s' % current_zipfile
        z.extractall(self.tempdir)

    def move_install_logs(self):
        """Move the installation logfiles in with the rest of the logs"""
        for inst_log in os.listdir(self.inst_logdir):
            shutil.move(self.inst_logdir + '\\' + inst_log, self.logdir)

    def get_logfile_info(self):
        """Get IP Address, GW Flavour Name, GW Version, pfxEnabled bool and tokenEnabled bool"""
        if os.path.exists(self.inst_logdir):
            self.move_install_logs()
        gw_info = gwInfoLookup()
        gw_info_dict = gw_info.gw_info_lookup(self.logdir)

        self.gw_ip = 'Unknown' if gw_info_dict['ip_address'] is None else gw_info_dict['ip_address']
        self.gw_flavour = 'Unknown' if gw_info_dict['flavour_name'] is None else gw_info_dict['flavour_name']
        self.gw_version = 'Unknown' if gw_info_dict['version'] is None else gw_info_dict['version']
        self.pfx_enabled = 'Unknown' if gw_info_dict['pfx_enabled'] is None else gw_info_dict['pfx_enabled']
        self.token_enabled = 'Unknown' if gw_info_dict['token_enabled'] is None else gw_info_dict['token_enabled']
        self.destdir = self.cwd + '\\' + self.gw_flavour + '_' + self.gw_ip

    def file_handler(self, current_zipfile):
        """Create Destination Folder for current GW's logfiles,

        move temp files into it then remove temp directory."""
        date_in_range = False
        logs_to_copy = ('TT_', '_OrderServer_', '_PriceServer_', '_FillServer_', '_OrderRouter',
                        'PRICEPROXY', 'ttmd_', 'AuditConvert_', '.mdmp', '_rpt', '.zip')
        if not os.path.exists(self.destdir):
            print 'Creating new directory \"%s\".' % (self.gw_flavour + '_' + self.gw_ip)
            os.makedirs(self.destdir)
        else:
            for folderName in os.listdir(self.cwd):
                if folderName == self.gw_flavour + '_' + self.gw_ip:
                    print 'Destination Folder already exists and is therefore being removed.'
                    shutil.rmtree(self.cwd + '\\' + folderName)
                    os.makedirs(self.destdir)

        print 'Moving files to %s' % self.destdir
        for fileName in os.listdir(self.logdir):
            current_logfile = None
            for keyword in logs_to_copy:
                if keyword in fileName and 'copy' not in fileName.lower():
                    if str(time.localtime().tm_year) in fileName:
                        filedate = str(fileName.split('_')[-1]).split('.')[-2]
                        file_epoch_time = getSecSinceEpoch(filedate)
                        if file_epoch_time >= (time.time() - (86400 * 10)):
                            date_in_range = True
                            current_logfile = self.logdir + '\\' + fileName

                        if current_logfile is not None:
                            current_logfile_size = os.path.getsize(current_logfile)
                            if current_logfile_size > 1937768448:
                                current_logfile_size_list = list(str(current_logfile_size / (1024 ** 2)))
                                print 'WARNING! The size of %s is %s.%s GB! AnaLog will skip this file.' % \
                                      (fileName, current_logfile_size_list[0], ''.join(current_logfile_size_list[1:]))
                            else:
                                try:
                                    shutil.move(current_logfile, self.destdir)
                                except IOError:
                                    pass

        print 'Moving Zip to %s' % self.destdir
        try:
            shutil.move(current_zipfile, self.destdir)
        except IOError:
            print 'ERROR! Unable to backup Zip file'

        print 'Removing temporary files...'
        if date_in_range:
            pass
        else:
            print 'ERROR! There are no logfiles within the required date range'
        shutil.rmtree(self.tempdir)

    def init_errors_list(self):
        """Initialise all_errors_list and create HTML file header and doc heading."""
        self.all_errors_list = []
        gwversion, pfxenabled, tokenenabled = self.gw_version, self.pfx_enabled, self.token_enabled
        if gwversion is None:
            gwversion = "Unknown"
        if pfxenabled is None:
            pfxenabled = "Unknown"
        if tokenenabled is None:
            tokenenabled = "Unknown"
        self.all_errors_list.append('<script type="text/javascript">\n' +
                                    'function Expand(id)\n' +
                                    '{var div = document.getElementById(\'detail\' + id);\n' +
                                    'if (div.style.display == \'\')\n' +
                                    '     div.style.display = \'none\';\n' +
                                    'else if (div.style.display == \'none\')\n' +
                                    '     div.style.display = \'\';}\n' +
                                    '</script>\n')
        self.all_errors_list.append('<html><body><font size=-1>\n\n')
        self.all_errors_list.append('<h1><a href=\"' + self.hyperlink_path +
                                    self.gw_flavour + '_' + self.gw_ip +
                                    '/\" title="Click here for the original logfiles">' +
                                    '_'.join([self.gw_flavour, self.gw_ip, gwversion]) + '</a></h1>\n')
        self.all_errors_list.append('<h3><font color=\"green\">')
        if pfxenabled is not None:
            self.all_errors_list.append('| PFXEnabled = %s |' % pfxenabled)
        if tokenenabled is not None:
            self.all_errors_list.append('| TokenEnabled = %s | ' % tokenenabled)
        self.all_errors_list.append('</font></h3>\n')

    @staticmethod
    def minidump_handler(directory):
        """Count minidump files with recent timestamps

        :param directory:
        """
        minidumpfiles = []
        minidumpcount = 0
        for fileName in os.listdir(directory):
            if '.mdmp' in fileName:
                if str(time.localtime().tm_year) in fileName:
                    filedate = str(fileName.split('_')[-1]).rstrip('.mdmp')
                    file_epoch_time = getSecSinceEpoch(filedate)
                    if file_epoch_time >= (time.time() - (86400 * 10)):
                        minidumpfiles.append(fileName)
                        minidumpcount += 1
                        crashserv = fileName.split('server')[0]
                        crashdate = fileName.split('_')[-1].rstrip('.mdmp')
                        for rptLog in os.listdir(directory):
                            if '_rpt.log' in rptLog:
                                if crashserv in rptLog:
                                    minidumpfiles.append(rptLog)
                                    break
                        for serverLog in os.listdir(directory):
                            if 'Server_' in serverLog:
                                if crashserv in serverLog:
                                    if crashdate in serverLog:
                                        minidumpfiles.append(serverLog)
                                        break
        return minidumpcount, minidumpfiles

    @staticmethod
    def is_not_user_requested_callstack(directory, filename, filedate_print_format):
        """
        Helper function to help actual minidumps to be differentiated from user requested call stacks

        :param directory:
        :param filename:
        :param filedate_print_format:
        :return:
        """
        log_entry_from_today = False
        minidumplog = file(directory + '\\' + filename, 'r')
        for line in minidumplog.readline():
            if filedate_print_format in line:
                log_entry_from_today = True
            if log_entry_from_today:
                if 'Not A Crash' in line:
                    return True
        minidumplog.close()
        return False

    def get_minidump_data(self):
        minidumpcount, minidumpfiles = self.minidump_handler(self.destdir)
        if minidumpcount > 0:
            self.all_errors_list.append('<font color=\"magenta\">| MINIDUMPs: %s |</font>\n' % (str(minidumpcount)))
        self.minidump_files = minidumpfiles

    def get_logfiles(self):
        self.log_list = os.listdir(self.destdir)
        self.log_list.sort(reverse=True)

    def list_of_logs(self):
        """Pass file name of current logfile to be analysed."""
        for logFile in self.log_list:
            yield logFile

    def check_logfile(self):
        """Get list of known log messages to be omitted from search results.

        Write log message severity counts for current GW to report file
        Write to temporary report list any log entries that met search criteria
        Create link to original, unfiltered logfile
        Compile Summary of severities and write to report
        Write to report list all log entries from the temporary report list."""

        if len(self.minidump_files) > 0:
            for minidump_file in self.minidump_files:
                self.all_errors_list.append('<br><a href=\"' + self.hyperlink_path +
                                            self.gw_flavour + '_' + self.gw_ip + '/' +
                                            minidump_file + '\">' +
                                            minidump_file + '</a>\n')
            self.all_errors_list.append('<hr>\n')

        logfile_counter = 0
        listofexceptions = logexceptions(self.gw_flavour)
        severitylist = ['WARNING', 'ERROR', 'CRITICAL']
        log_id_match_pattern = re.compile('[1-2][0-9][0-9][0-9][0-9][0-9][0-9][0-9]')
        logfile_list_generator = self.list_of_logs()

        while True:
            try:
                current_logfile = logfile_list_generator.next()
            except StopIteration:
                break

            tmplist = []
            log_id_summary_list = []
            log_id_full_list = []
            log_alert_dict = {}
            log_severity_list = []
            log_severity_counts = []
            log_alert_list = []
            warnings = 0
            errors = 0
            criticals = 0
            log_id_zero = 0

            if current_logfile is not None:
                if '.mdmp' in current_logfile:
                    pass
                elif '.zip' in current_logfile:
                    pass
                else:
                    full_log_path = self.destdir + '\\' + current_logfile
                    logfilename = '_'.join(current_logfile.split('\\')[-2:])
                    logfile_link = '<a href=\"' + self.hyperlink_path + \
                                   self.gw_flavour + '_' + self.gw_ip + '/' + \
                                   logfilename + '">' + \
                                   'Click Here to view the full logfile</a>\n'
                    print 'Currently analising %s' % (current_logfile.split('\\')[-1])
                    logfile_being_checked = file(full_log_path, 'r')
                    for logfile_entry in logfile_being_checked.readlines():
                        log_id = None
                        append = False
                        exception_match = False

                        for exception in listofexceptions:
                            if exception.match(logfile_entry) is not None:
                                exception_match = True

                        if not exception_match:
                            for severity in severitylist:
                                if ''.join(['| ', severity, ' |']) in logfile_entry:
                                    if severitylist.index(severity) == 0:
                                        warnings += 1
                                        append = True
                                    if severitylist.index(severity) == 1:
                                        errors += 1
                                        append = True
                                    if severitylist.index(severity) == 2:
                                        criticals += 1
                                        append = True

                        if '| 00000000 |' in logfile_entry:
                            logfile_entry = '<font color=\"red\">' + logfile_entry + '</font>'
                            log_id_zero += 1
                            append = True

                        if append:
                            tmplist.append(logfile_entry + '<br>')

                        if not exception_match:
                            for log_entry_element in logfile_entry.split('|'):
                                log_entry_element = log_entry_element.strip()
                                if log_id_match_pattern.match(log_entry_element):
                                    log_id = log_entry_element

                            if log_id is not None:
                                if log_id not in log_id_summary_list:
                                    log_id_summary_list.append(log_id)
                                log_id_full_list.append(log_id)

                    # create severity counts list
                    if warnings + errors + criticals + log_id_zero > 0:
                        if warnings > 0:
                            log_severity_counts.append('%ss : %d' % (severitylist[0], warnings))
                        if errors > 0:
                            log_severity_counts.append('%ss : %d' % (severitylist[1], errors))
                        if criticals > 0:
                            log_severity_counts.append('%ss : %d' % (severitylist[2], criticals))
                        if log_id_zero > 0:
                            log_severity_counts.append('%ss : %d' % ('00000000', log_id_zero))
                        log_severity_list.append('<div style="color:maroon; font-weight:bold;">| ' +
                                                 ' | '.join(log_severity_counts) +
                                                 ' |</div>\n')

                    # create log_alert_dict
                    for log_id in log_id_summary_list:
                        if log_id_full_list.count(log_id) > 1600:
                            log_id_count = log_id_full_list.count(log_id) + 1
                            log_alert_dict[log_id] = str(log_id_count)

                    # create log_alert_list
                    if len(log_alert_dict) > 0:
                        log_alert_list.append('<div style="color:navy; font-weight:bold;">' +
                                              '<br>WARNING! This logfile contains a large number ' +
                                              'of the following messages:' +
                                              '</div>\n<div>\n')
                        for k, v in log_alert_dict.iteritems():
                            lci_url = '<a href=\"http://cmweb/lci/message/view/id/%s\">%s</a> ' % (k, k)
                            alert_string = lci_url + 'was logged ' + v + ' times.' + '<br>\n'
                            log_alert_list.append(alert_string)
                        log_alert_list.append('</div>\n')

                    if len(tmplist) + len(log_alert_list) > 0:
                        logfile_number = ''.join(['logfile', str(logfile_counter)])
                        # append logfile name header - log contents will expand from here
                        self.all_errors_list.append('<br>&nbsp;<br><div id="' + logfile_number + '" ' +
                                                    'style="color:blue; font-weight:bold; cursor:pointer;" ' +
                                                    'onclick="Expand(this.id);" ' +
                                                    'onmouseover="this.style.color = "cyan";" ' +
                                                    'onmouseout="this.style.color = "blue";">' +
                                                    logfilename +
                                                    '</div>\n<br>\n')

                        tmplist.append('<p>&nbsp;</p>')

                        self.all_errors_list.extend(log_severity_list)
                        self.all_errors_list.extend(log_alert_list)
                        self.all_errors_list.append('<div><br>\n' +
                                                    '<div id="detail' + logfile_number + '" style="display:none;">\n' +
                                                    '<p>' + logfile_link + '</p>' +
                                                    '\n<div>\n')
                        self.all_errors_list.extend(tmplist)
                        self.all_errors_list.append('<hr>\n')
                        self.all_errors_list.append('</div></div></div>\n\n')

                    logfile_being_checked.close()

            logfile_counter += 1

        reportname = self.gw_flavour + '_' + self.gw_ip
        self.create_report(reportname)

    def create_report(self, reportname):
        """Write results and HTML footer to report list"""
        # if not any(error_message in str(self.all_errors_list) for error_message in ['WARNING', 'ERROR', 'CRITICAL']):
        #     self.all_errors_list.append('<h3>AnaLog found no issues!</h3>\n')

        daylight = 'CST' if time.localtime()[-1] == 0 else 'CDT'
        currtime = str(time.asctime())
        self.all_errors_list.append('<p><dd><dd><font color=\"gray\" size=1>Log results provided by AnaLog.py')
        self.all_errors_list.append('<dd><dd>Report Create Time = ' + (' '.join([currtime, daylight])) + '</font></p>')
        self.all_errors_list.append('\n\n</font></body></html>')

        reportfile = self.cwd + '\\' + reportname + '_' + str(time.time()).split('.')[-2] + '.html'
        f = file(reportfile, 'w')
        for error in self.all_errors_list:
            f.write(error)
        f.close()

        formatted_reportfile = ((reportfile.lstrip(self.cwd)).replace('_', ' ')).replace('.html', '')
        f = file(self.today_file, 'a')
        f.write('<h3 style="font-family: Arial; text-align:center;"><a href=\"' +
                reportfile.replace(self.cwd + '\\', 'http://10.31.60.183:8080/') + '\">' +
                formatted_reportfile + '</a></h3>\n')
        f.close()

        self.all_errors_list = []

    def cleanup(self):
        """Clean up and archive data."""
        if not os.path.exists(self.archivedir):
            os.makedirs(self.archivedir)
        print 'Archiving data to \"%s\".' % (self.archivedir.split('\\')[-1])
        cwd_list = os.listdir(self.cwd)
        for item in cwd_list:
            if 'archive_' in item:
                pass
            elif '.html' in str(item):
                pass
            else:
                if not os.path.exists(self.archivedir + '\\' + item):
                    os.makedirs(self.archivedir + '\\' + item)
                for file_for_archiving in os.listdir(self.cwd + '\\' + item):
                    shutil.move(self.cwd + '\\' + item + '\\' + file_for_archiving, self.archivedir + '\\' + item)
                os.removedirs(self.cwd + '\\' + item)

        # remove temporary unzip directory
        shutil.rmtree(self.source_log_path)

    def post_to_server(self):
        """Send report files to the web server."""
        item_list = []
        print 'Posting Gateway Log Report to the server.'
        for item in os.listdir(self.cwd):
            if '.html' not in item:
                pass
            else:
                item_list.append(item)
                shutil.copy(self.cwd + '\\' + item, self.log_results_dir)
                shutil.move(self.cwd + '\\' + item, self.archivedir)
        time.sleep(5)
        self.update_google_group(item_list)

    def update_google_group(self, item_list):
        """Generate an email summarizing the AnaLog run and post it to the AnaLog Google Group"""
        html_file_name = self.today_file.split('\\')[-1]
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        server = smtplib.SMTP('mail.int.tt.local')
        server.ehlo()

        text_block = ['\nThe following logfile reports requested by ',
                      getpass.getuser(),
                      ' are now ready and have been posted here: ',
                      'http://10.31.60.183:8080/',
                      html_file_name,
                      '<br><br>'
                      'NOTE: If you need to visit this link later and you\'re prompted to login, '
                      'please use Administrator 12345678.'
                      '<br><br>']

        for item in item_list:
            text_block.append(item + '<br>')

        attachment = MIMEText(''.join(text_block), 'html')

        msg = MIMEMultipart('alternative')
        msg['Subject'] = 'AnaLog Results from ' + getDateStamp()
        msg['From'] = 'analog@tradingtechnologies.com'
        msg['To'] = 'analog@tradingtechnologies.com'
        msg.preamble = 'AnaLog Results'
        msg.attach(attachment)

        sender = 'analog@tradingtechnologies.com'
        recipient = 'analog@tradingtechnologies.com'
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()

    def run_analog(self):
        zipfile_count = 1
        if not self.today_file:
            print 'ERROR! It seems like I was unable to login to the server.'
        else:
            self.setup_class()
            self.grab_original_zip_files()
            zip_list_count = self.get_log_zips()
            zip_list_generator = self.list_of_zips()
            while zipfile_count <= zip_list_count:
                try:
                    current_zipfile = zip_list_generator.next()
                    self.log_unzip(current_zipfile)
                    self.get_logfile_info()
                    self.file_handler(current_zipfile)
                    self.init_errors_list()
                    self.get_minidump_data()
                    self.get_logfiles()
                    self.check_logfile()
                    zipfile_count += 1
                except:
                    print '\nERROR! Unable to continue Analysing logfile zip %s;' % current_zipfile
                    print 'moving on to next Zip file.\n'
                    zipfile_count += 1
            self.cleanup()
            self.post_to_server()


if __name__ == "__main__":
    AnaLog = AnaLog()
    AnaLog.run_analog()