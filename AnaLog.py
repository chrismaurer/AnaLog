'''TT Gateway Logfile Analiser

This script extracts TT Logfile Zips and analises them, removing all "background noise" from the files. 
The meaningful error messages are compiled into a report and posted to the AnaLog webserver.
'''

__author__ = 'Chris Maurer (chris.maurer@tradingtechnologies.com)'
__version__ = '2.1'

import os
import time
import logging
import shutil
import zipfile
import subprocess
import getpass
import re
import smtplib
from gwInfoLookup import gwInfoLookup 
from logExceptions import logExceptions
from Timestamp import getTimeStamp, getDateStamp, getSecSinceEpoch
from htmlHandler import catalog_by_date

log = logging.getLogger(__name__)

class AnaLog():

    @classmethod
    def setUpClass(self):
        self.allErrorsList = []
        self.severitySummary = []
        self.miniDumpFiles = []
        self.zipList = []
        self.logList = []
        self.gwFlavour = None
        self.gwIP = None
        self.gwVersion = None
        self.pfxEnabled = None
        self.tokenEnabled = None
        self.cwd = r'C:\temp\logs'
        self.tempDir = self.cwd+'\\tmp'
        self.logDir = self.tempDir+'\\tt\logfiles'
        self.inst_logDir = self.logDir+'\\install'
        self.configDir = self.tempDir+'\\tt\config'
        self.sourceLogPath = r'C:\temp\logtemp'
        self.destDir = None
        self.archiveDir = r'\\10.31.60.183\c$\log_archives' + '\\' + 'archive_' + getDateStamp() + '_' + getTimeStamp()
        self.log_results_dir = r'\\10.31.60.183\c$\AnaLog'
        self.hyperlink_path = r'file://///10.31.60.183/c$/log_archives/archive_' + getDateStamp() + '_' + getTimeStamp() + '/'
        self.today_file = catalog_by_date()
        
        #Create local directories of they don't already exist
        if not os.path.exists(r'c:\temp'):
            os.mkdir(r'c:\temp')
        if not os.path.exists(self.cwd):
            os.mkdir(self.cwd)
        if not os.path.exists(self.sourceLogPath):
            os.mkdir(self.sourceLogPath)

    def get_user_logon_creds(self):
        netUseCmd = r'net use \\10.31.60.183\c$ /user:10.31.60.183\Administrator 12345678'
        login_response = subprocess.Popen(netUseCmd, stdout=subprocess.PIPE).communicate()
        if 'The command completed successfully' in str(login_response):
            return True
        else:
            return False

    def grabOriginalZipFiles(self):
        '''Get path to the original ZIP files and copy them to local PC'''
        filename = r'C:\temp\AnaLog.ini'
        originalZipFilePath = None

        while True:
            try:
                f = file(filename, 'r')
                hist = f.readline()
                f.close()
            except:
                pass
                hist = None
            getZipFilePath = raw_input('Please enter the path of the Zip files to analise [%s] : ' % (hist))
            if len(getZipFilePath) > 0:
                f = file(filename, 'w')
                f.write(getZipFilePath)
                f.close()
            originalZipFilePath = hist if len(getZipFilePath) == 0 else getZipFilePath
            if originalZipFilePath == None:
                print 'ERROR! Could not locate Original Zip Files!'
                raw_input('Press ENTER to re-try.')
            else:
                print 'Copying Zip files from %s...' % (originalZipFilePath)
                for zipFile in os.listdir(originalZipFilePath):
                    if '.zip' in zipFile:
                        shutil.copy(originalZipFilePath + '\\' + zipFile, self.sourceLogPath)
                break

    def getLogZips(self):
        for fileName in os.listdir(self.sourceLogPath):
            if '.zip' in fileName:
                self.zipList.append(fileName)
        zipFileCount = len(self.zipList)
        if zipFileCount == 0:
            print 'ERROR! There are no logfile ZIPs in the specified directory!'
        return zipFileCount

    def listOfZips(self):
        '''Pass file name of current logfile zip to be extracted.'''
        for zipFileName in self.zipList:
            zipFile = self.sourceLogPath + '\\' + zipFileName
            yield zipFile

    def logUnzip(self, currentZipFile):
        z = zipfile.ZipFile(currentZipFile)
        for folderName in os.listdir(self.cwd):
            if folderName == 'tmp':
                print 'An old temp folder was found and is therefore being removed.'
                shutil.rmtree(self.cwd + '\\' + folderName)
        print 'Extracting Zip: %s' % (currentZipFile)
        z.extractall(self.tempDir)
        self.deltreeList = os.listdir(self.cwd)

    def move_install_logs(self):
        for inst_log in os.listdir(self.inst_logDir):
            shutil.move(self.inst_logDir + '\\' + inst_log, self.logDir)

    def getLogfileInfo(self):
        if os.path.exists(self.inst_logDir):
            self.move_install_logs()
        gw_info = gwInfoLookup()
        gw_info_dict = gw_info.gw_info_lookup(self.logDir)

        self.gwIP = 'Unknown' if gw_info_dict['ip_address'] == None else gw_info_dict['ip_address']
        self.gwFlavour = 'Unknown' if gw_info_dict['flavour_name'] == None else gw_info_dict['flavour_name']
        self.gwVersion = 'Unknown' if gw_info_dict['version'] == None else gw_info_dict['version'] 
        self.pfxEnabled = 'Unknown' if gw_info_dict['pfx_enabled'] == None else gw_info_dict['pfx_enabled'] 
        self.tokenEnabled = 'Unknown' if gw_info_dict['token_enabled'] == None else gw_info_dict['token_enabled']
        self.destDir = self.cwd + '\\' + self.gwFlavour + '_' + self.gwIP

    def fileHandler(self, currentZipFile):
        '''Create Destination Folder for current GW's logfiles,

        move temp files into it then remove temp directory.'''

        dateInRange = False
        logsToCopy = ('TT_', '_OrderServer_', '_PriceServer_', '_FillServer_', '_OrderRouter',\
                         'PRICEPROXY', 'ttmd_', 'AuditConvert_', '.mdmp', '_rpt', '.zip')
        try:
            print 'Creating new directory \"%s\".' % (self.gwFlavour + '_' + self.gwIP)
            os.makedirs(self.destDir)
        except:
            for folderName in os.listdir(self.cwd):
                if folderName == self.gwFlavour + '_' + self.gwIP:
                    print 'Destination Folder already exists and is therefore being removed.'
                    shutil.rmtree(self.cwd + '\\' + folderName)
                    os.makedirs(self.destDir)

        print 'Moving files to %s' % (self.destDir)
        keyword = None
        for fileName in os.listdir(self.logDir):
            currentLogfile = None
            for keyword in logsToCopy:
                if keyword in fileName and 'copy' not in fileName.lower():
                    if str(time.localtime().tm_year) in fileName:
                        fileDate = str(fileName.split('_')[-1]).split('.')[-2]
                        fileEpochTime = getSecSinceEpoch(fileDate)
                        if fileEpochTime >= (time.time() - (86400 * 10)):
                            dateInRange = True
                            currentLogfile = self.logDir + '\\' + fileName

                        if currentLogfile != None:
                            currentLogfileSize = os.path.getsize(currentLogfile)
                            if currentLogfileSize > 2000000000:
                                currentLogfileSize_list = list(str(currentLogfileSize / (1024**2)))
                                print 'WARNING! The size of %s is %s.%s GB! AnaLog will skip this file.' % (fileName,
                                                                                                            currentLogfileSize_list[0],
                                                                                                            ''.join(currentLogfileSize_list[1:]))
                            else:
                                try:
                                    shutil.move(currentLogfile, self.destDir)
                                except:
                                    pass

        print 'Moving Zip to %s' % (self.destDir)
        try:
            shutil.move(currentZipFile, self.destDir)
        except:
            print 'ERROR! Unable to backup Zip file'

        print 'Removing temporary files...'
        if dateInRange == True:
            pass
        else:
            print 'ERROR! There are no logfiles within the required date range'
        shutil.rmtree(self.tempDir)

    def initErrorsList(self):
        '''Initialise allErrorsList and create HTML file header and doc heading.''' 
        self.allErrorsList = []
        gwVersion, pfxEnabled, tokenEnabled = self.gwVersion, self.pfxEnabled, self.tokenEnabled
        if gwVersion == None:
            gwVersion = "Unknown"
        if pfxEnabled == None:
            pfxEnabled = "Unknown"
        if tokenEnabled == None:
            tokenEnabled = "Unknown"
        self.allErrorsList.append('<script type="text/javascript">\n' + \
                                  'function Expand(id)\n' + \
                                  '{var div = document.getElementById(\'detail\' + id);\n' + \
                                  'if (div.style.display == \'\')\n'
                                  '     div.style.display = \'none\';\n' + \
                                  'else if (div.style.display == \'none\')\n' + \
                                  '     div.style.display = \'\';}\n' + \
                                  '</script>\n')
        self.allErrorsList.append('<html><body><font size=-1>\n\n')
        self.allErrorsList.append('<h1><a href=\"' + self.hyperlink_path + \
                                  self.gwFlavour + '_' + self.gwIP + '/\" title="Click here for the original logfiles">' + \
                                  '_'.join([self.gwFlavour, self.gwIP, gwVersion]) + '</a></h1>\n')
        self.allErrorsList.append('<h3><font color=\"green\">')
        if pfxEnabled != None:
            self.allErrorsList.append('| PFXEnabled = %s |' % (pfxEnabled))
        if tokenEnabled != None:
            self.allErrorsList.append('| TokenEnabled = %s | ' % (tokenEnabled))
        self.allErrorsList.append('</font></h3>\n')

    def miniDumpHandler(self, directory):
        '''Count minidump files with recent timestamps'''
        miniDumpFiles = []
        miniDumpCount = 0
        for fileName in os.listdir(directory):
            if '.mdmp' in fileName:
                if str(time.localtime().tm_year) in fileName:
                    fileDate = str(fileName.split('_')[-1]).rstrip('.mdmp')
                    fileEpochTime = getSecSinceEpoch(fileDate)
                    if fileEpochTime >= (time.time() - (86400 * 10)):
                        miniDumpFiles.append(fileName)
                        miniDumpCount += 1
                        crashServ = fileName.split('server')[0]
                        crashDate = fileName.split('_')[-1].rstrip('.mdmp')
                        for rptLog in os.listdir(directory):
                            if '_rpt.log' in rptLog:
                                if crashServ in rptLog:
                                    miniDumpFiles.append(rptLog)
                                    break
                        for serverLog in os.listdir(directory):
                            if 'Server_' in serverLog:
                                if crashServ in serverLog:
                                    if crashDate in serverLog:
                                        miniDumpFiles.append(serverLog)
                                        break
        return miniDumpCount, miniDumpFiles

    def is_not_user_requested_callstack(self, directory, fileName, fileDatePrintFormat):
        log_entry_from_today = False
        MiniDumpLog = file(directory + '\\' + fileName, 'r')
        for line in MiniDumpLog.readline():
            if fileDatePrintFormat in line:
                log_entry_from_today = True
            if log_entry_from_today:
                if 'Not A Crash' in line:
                    return True
        return False

    def getMiniDumpData(self):
        miniDumpCount, miniDumpFiles = self.miniDumpHandler(self.destDir)
        if miniDumpCount > 0:
            self.allErrorsList.append('<font color=\"magenta\">| MINIDUMPs: %s |</font>\n' % (str(miniDumpCount)))
        self.miniDumpFiles = miniDumpFiles

    def getLogFiles(self):
        self.logList = os.listdir(self.destDir)
        self.logList.sort(reverse=True)

    def listOfLogs(self):
        '''Pass file name of current logfile to be analised.'''
        for logFile in self.logList:
            yield logFile

    def checkLogfile(self):
        '''Get list of known log messages to be omitted from search results.
        
        Write log message severity counts for current GW to report file
        Write to temporary report list any log entries that met search criteria
        Create link to original, unfiltered logfile
        Compile Summary of severities and write to report
        Write to report list all log entries from the temporary report list.'''

        if len(self.miniDumpFiles) > 0:
            for miniDumpFile in self.miniDumpFiles:
                self.allErrorsList.append('<br><a href=\"' + self.hyperlink_path + \
                                           self.gwFlavour + '_' + self.gwIP + '/' + \
                                          miniDumpFile + '\">' + \
                                          miniDumpFile + '</a>\n')
            self.allErrorsList.append('<hr>\n')

        logfile_counter = 0
        listOfExceptions = logExceptions(self.gwFlavour)
        severityList = ['WARNING', 'ERROR', 'CRITICAL']
        log_id_match_pattern = re.compile('[1-2][0-9][0-9][0-9][0-9][0-9][0-9][0-9]')
        log = self.listOfLogs()

        while True:
            try:
                currentLogfile = log.next()
            except:
                currentLogfile = None
                break

            tmpList = []
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

            if currentLogfile != None:
                if '.mdmp' in currentLogfile: pass
                elif '.zip' in currentLogfile: pass
                else:
                    fullLogPath = self.destDir + '\\' + currentLogfile
                    logfilename = '_'.join(currentLogfile.split('\\')[-2:])
                    logfile_link = '<a href=\"' + self.hyperlink_path + \
                                   self.gwFlavour + '_' + self.gwIP + '/' + \
                                   logfilename + '">' + \
                                   'Click Here to view the full logfile</a>\n'
                    print 'Currently analising %s' % (currentLogfile.split('\\')[-1])
                    logfile_being_checked = file(fullLogPath, 'r')
                    for logfile_entry in logfile_being_checked.readlines():
                        log_id = None
                        append = False
                        exception_match = False

                        for exception in listOfExceptions:
                            if exception.match(logfile_entry) != None:
                                exception_match = True

                        if not exception_match:
                            for severity in severityList:
                                if ''.join(['| ', severity, ' |']) in logfile_entry:
                                    if severityList.index(severity) == 0:
                                        warnings += 1
                                        append = True
                                    if severityList.index(severity) == 1:
                                        errors += 1
                                        append = True
                                    if severityList.index(severity) == 2:
                                        criticals += 1
                                        append = True

                        if '| 00000000 |' in logfile_entry:
                            logfile_entry = '<font color=\"red\">' + logfile_entry + '</font>'
                            log_id_zero +=1 
                            append = True

                        if append:
                            tmpList.append(logfile_entry + '<br>')

                        if not exception_match:
                            for log_entry_element in logfile_entry.split('|'):
                                log_entry_element = log_entry_element.strip()
                                if log_id_match_pattern.match(log_entry_element):
                                    log_id = log_entry_element

                            if log_id != None:
                                if log_id not in log_id_summary_list:
                                    log_id_summary_list.append(log_id)
                                log_id_full_list.append(log_id)

                    # create severity counts list
                    if warnings + errors + criticals + log_id_zero > 0:
                        if warnings > 0: log_severity_counts.append('%ss : %d' % (severityList[0], warnings))
                        if errors > 0: log_severity_counts.append('%ss : %d' % (severityList[1], errors))
                        if criticals > 0: log_severity_counts.append('%ss : %d' % (severityList[2], criticals))
                        if log_id_zero > 0: log_severity_counts.append('%ss : %d' % ('00000000', log_id_zero))
                        log_severity_list.append('<div style="color:maroon; font-weight:bold;">| ' + \
                                                  ' | '.join(log_severity_counts) + \
                                                  ' |</div>\n')

                    # create log_alert_dict
                    for log_id in log_id_summary_list:
                        if log_id_full_list.count(log_id) > 1600:
                            log_id_count = log_id_full_list.count(log_id) + 1
                            log_alert_dict[log_id] = str(log_id_count)

                    # create log_alert_list
                    if len(log_alert_dict) > 0:
                        log_alert_list.append('<div style="color:navy; font-weight:bold;">' + \
                                              '<br>WARNING! This logfile contains a large number of the following messages:' + \
                                              '</div>\n<div>\n')
                        for k, v in log_alert_dict.iteritems():
                            lci_url = '<a href=\"http://cmweb/lci/message/view/id/%s\">%s</a> ' % (k, k)
                            alert_string = lci_url + 'was logged ' + v + ' times.' + '<br>\n'
                            log_alert_list.append(alert_string)
                        log_alert_list.append('</div>\n')

                    if len(tmpList) + len(log_alert_list) > 0:
                        logfile_number = ''.join(['logfile', str(logfile_counter)])
                        # append logfile name header - log contents will expand from here
                        self.allErrorsList.append('<br>&nbsp;<br><div id="' + logfile_number + '" ' + \
                                                  'style="color:blue; font-weight:bold; cursor:pointer;" ' + \
                                                  'onclick="Expand(this.id);" ' + \
                                                  'onmouseover="this.style.color = "cyan";" ' + \
                                                  'onmouseout="this.style.color = "blue";">' + \
                                                  logfilename + \
                                                  '</div>\n<br>\n')
                        
                        tmpList.append('<p>&nbsp;</p>')

                        self.allErrorsList.extend(log_severity_list)
                        self.allErrorsList.extend(log_alert_list)
                        self.allErrorsList.append('<div><br>\n' + \
                                                  '<div id="detail' + logfile_number + '" style="display:none;">\n' + \
                                                  '<p>' + logfile_link + '</p>' + \
                                                  '\n<div>\n')
                        self.allErrorsList.extend(tmpList)
                        self.allErrorsList.append('<hr>\n')
                        self.allErrorsList.append('</div></div></div>\n\n')

#                if len(self.allErrorsList) == 0:
#                    self.allErrorsList.append('<h3>AnaLog found no issues!</h3>\n')

            logfile_counter += 1

        reportName = self.gwFlavour + '_' + self.gwIP
        self.createReport(reportName)

    def createReport(self, reportName):
        '''Write results and HTML footer to report list'''
        daylight = 'CST' if time.localtime()[-1] == 0 else 'CDT' 
        currTime = str(time.asctime())
        self.allErrorsList.append('<p><dd><dd><font color=\"gray\" size=1>Log results provided by AnaLog.py')
        self.allErrorsList.append('<dd><dd>Report Create Time = ' + (' '.join([currTime,daylight])) + '</font></p>')
        self.allErrorsList.append('\n\n</font></body></html>')

        reportFile = self.cwd + '\\' + reportName + '_' + str(time.time()).split('.')[-2] + '.html'
        f = file(reportFile, 'w')
        for error in self.allErrorsList:
            f.write(error)
        f.close()

        formatted_reportFile = ((reportFile.lstrip(self.cwd)).replace('_', ' ')).replace('.html', '')
        f = file(self.today_file, 'a')
        f.write('<h3 style="font-family: Arial; text-align:center;"><a href=\"' + \
                reportFile.replace(self.cwd + '\\', 'http://10.31.60.183:8080/') + '\">' + \
                formatted_reportFile + '</a></h3>\n')
        f.close()
        
        self.allErrorsList = []

    def cleanUp(self):
        '''Clean up and archive data.'''
        try:
            os.makedirs(self.archiveDir)
        except:
            pass
        print 'Archiving data to \"%s\".' % (self.archiveDir.split('\\')[-1])
        for item in os.listdir(self.cwd):
            if 'archive_' in item: pass
            elif '.html' in str(item): pass
            else:
                try:
                    os.makedirs(self.archiveDir + '\\' + item)
                    for file_for_archiving in os.listdir(self.cwd + '\\' + item):
                        shutil.move(self.cwd + '\\' + item + '\\' + file_for_archiving, self.archiveDir + '\\' + item)
                    os.removedirs(self.cwd + '\\' + item)
                except: pass

        # remove temporary unzip directory
        shutil.rmtree(self.sourceLogPath)

    def postToServer(self):
        '''Send report files to the webserver.'''
        item_list = []
        print 'Posting Gateway Log Report to the server.'
        for item in os.listdir(self.cwd):
            if '.html' not in item: pass
            else:
                item_list.append(item)
                shutil.copy(self.cwd + '\\' + item, self.log_results_dir)
                shutil.move(self.cwd + '\\' + item, self.archiveDir)
        time.sleep(5)
        self.updateGoogleGroup(item_list)

    def updateGoogleGroup(self, item_list):
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

    def runAnaLog(self):
        zipFileCount = 1
        if self.get_user_logon_creds():
            self.setUpClass()
            self.grabOriginalZipFiles()
            zipListCount = self.getLogZips()
            zip_list_generator = self.listOfZips()
            while zipFileCount <= zipListCount:
                try:
                    currentZipFile = zip_list_generator.next()
                    self.logUnzip(currentZipFile)
                    self.getLogfileInfo()
                    self.fileHandler(currentZipFile)
                    self.initErrorsList()
                    self.getMiniDumpData()
                    self.getLogFiles()
                    self.checkLogfile()
                    zipFileCount += 1
                except:
                    print 'ERROR! Unable to continue Analising logfile zip %s; moving on to next Zip file.' % currentZipFile
                    zipFileCount += 1
            self.cleanUp()
            self.postToServer()
        else:
            print 'ERROR! It seems like I was unable to login to the server.'

if __name__ == "__main__":
    AnaLog = AnaLog()
    AnaLog.runAnaLog()
