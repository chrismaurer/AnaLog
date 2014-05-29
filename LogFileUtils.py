import re


# This function returns true if a given severity is found in a log file.
# The valid severity values are: INFO, WARNING, ERROR, CRITICAL or None if
# you don't want to include the severity as part the search.
# The message should be None if you don't want to include the message as part
# of the search or a compiled regular expression object which represents the message
# as a regular expression.
# This function assumes the file is a TT-style log file in which the
# severity is as:  DATE TIME | PROCESS/MODE | THREAD ID | SEVERITY | NUMBER | MESSAGE
# (anything) + some exact text with a variable name in the middle + (anything)
#message = re.compile( r".*notifyTraderMessage Trader \(\w+\) GTC download is complete.*", re.I )
# (anything) + some exact text + (anything)
#message = re.compile( r".*sequence numbers mismatch.*", re.I )
def isMessageInLogFile( fileName, severity, message, exceptions ):

    matchedLines = []

    if( None == severity ):
        severityPattern = re.compile( r".*" )
    else:
        severityPattern = re.compile( r".*[0-9]+ \| %s \| [0-9]+ \|.*" % severity, re.I )

    if( None == message ):
        messagePattern = re.compile( r".*" )
    else:
        messagePattern = message


    file_desc = open( fileName, "rU" )

    line = file_desc.readline()
    while( "" != line ):

        line = file_desc.readline()

        if( None != severityPattern.match( line ) and
            None != messagePattern.match( line ) ):
            matchedLines.append( line )

    file_desc.close()

    notExceptionLines = []
    for line in matchedLines:
            
        foundInExceptions = False
            
        for exception in exceptions:
            if( None != exception.match( line ) ):
                foundInExceptions = True

        if( False == foundInExceptions ):
            notExceptionLines.append( line )


    return notExceptionLines




