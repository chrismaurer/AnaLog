#~Filename: Timestamp.py
#~Library function that uses time functions to create time, date, datetime stamps.

import time
from datetime import datetime
#from pyrate.builder import Builder
#from pyrate.ttapi.manager import TTAPIManager

def getTimeStamp():
    '''Returns the current local time in 24-hour time format'''
    timelist = []
    timelist.extend(time.asctime())
    timeElem = (''.join(timelist[11:19])).split(':')
    timeStamp = ''.join(timeElem)
    return timeStamp

def getDateStamp():
    '''Returns the current local date in TT date format'''
    dateElem = list(time.localtime(time.time()))
    dateDay = str(dateElem[2]).zfill(02)
    dateMnth = str(dateElem[1]).zfill(02)
    dateYear = str(dateElem[0])
    dateList = [dateYear, dateMnth, dateDay]
    dateStamp = '-'.join(dateList)
    return dateStamp

def getSecSinceEpoch(datestamp):
    '''Returns the datestamp passed expressed in seconds since the Epoch.
    
    Expects the following format: YYYY-MM-DD'''
    dateList = datestamp.split('-')
    c_time = datetime(int(dateList[0]), int(dateList[1]), int(dateList[2])).ctime()
    timeTuple = time.strptime(c_time)
    secSinceEpoch = time.mktime(timeTuple)
    return secSinceEpoch