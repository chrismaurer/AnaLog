#~AnaLog
#~This program analises logfiles

'''.'''

__author__ = 'Chris Maurer (chris.maurer@tradingtechnologies.com)'
__version__ = '1.13'

import re, os, logging, copy

log = logging.getLogger(__name__)

class gwInfoLookup():

    @classmethod
    def setUpClass(self):
        self.gw_info = {'ip_address' : None, 'flavour_name' : None, 'version' : None, 'pfx_enabled' : None, 'token_enabled' : None}
        self.price_order_server_logfiles = []

    def get_ip_address(self, directory):
        '''Get GW IP Address from ipconfig.txt log.'''
        ip_address = None
        for filename in os.listdir(directory):
            if 'ipconfig.txt' in filename:
                ipconfigFile = directory + '\\' + filename
                f = open(ipconfigFile, 'rU')
                for line in f.readlines():
                    if 'IPv4 Address' in line or 'IP Address' in line:
                        if 'Autoconfiguration' in line: pass
                        else: break
                ip_address = str(line.split(': ')[1]).rstrip()
                ip_address = ip_address.replace('(Preferred)', '')
                f.close()

        self.gw_info['ip_address'] = ip_address
    
    def create_price_order_server_logfiles_list(self, directory):
        filename_elements = ['_OrderServer_', '_PriceServer_']
        for logfile in os.listdir(directory):
            if any(filename_element in logfile for filename_element in filename_elements):
                logfile = directory + '\\' + logfile
                self.price_order_server_logfiles.append(logfile)
    
        for price_order_server_logfile in self.price_order_server_logfiles:
            if 'Copy of' in price_order_server_logfile:
                self.price_order_server_logfiles.remove(price_order_server_logfile)

        self.price_order_server_logfiles.sort(reverse=True)

    def get_price_order_server_logfiles(self):
        server_logfiles = copy.copy(self.price_order_server_logfiles)
        for server_logfile in server_logfiles:
            yield server_logfile

    def get_details(self, directory):
        logfile = None
        startup_logfile = None

        logfiles = self.get_price_order_server_logfiles()
        while startup_logfile == None:
            logfile = logfiles.next()
            if os.path.getsize(logfile) < 3000:
                continue
            else:
                try:
                    startup_logfile = logfile
                    f = open(logfile, 'rU')
                    for line in f.readlines():
                        if re.search('Starting up .*Server', line, re.I) != None:
                            startup_logfile = logfile
                            break
                        else:
                            startup_logfile = None
                        f.close()
                except:
                    print 'Unable to find any logfiles containing server startup logging!'

        print '[DEBUG] logfile = %s' % (startup_logfile)
        f = open(startup_logfile, 'rU')
        for line in f.readlines():
            if self.gw_info['version'] == None:
                if re.search('Starting up .*Server', line, re.I) != None:
                    try:
                        if 'PRICE SERVER' in line or 'ORDER SERVER' in line:
                            self.gw_info['version'] = (line.split(' '))[-4]
                        else:
                            self.gw_info['version'] = (line.split(' '))[-1].rstrip('.\n')
                        if self.gw_info['flavour_name'] == None:
                            if 'PRICE SERVER' in line or 'ORDER SERVER' in line:
                                self.gw_info['flavour_name'] = (line.split(' '))[-1].rstrip('.\n')
                            elif any(item in line for item in [' OrderServer ', ' PriceServer ',
                                                               'ORDERSERVER', 'PRICESERVER']):
                                self.gw_info['flavour_name'] = (line.split(' '))[-3]
                            elif 'OrderServer' in line:
                                self.gw_info['flavour_name'] = (line.split(' '))[-2].rstrip('OrderServer')
                            elif 'PriceServer' in line:
                                self.gw_info['flavour_name'] = (line.split(' '))[-2].rstrip('PriceServer')
                            else:
                                print 'ERROR: Unable to determine the Gateway Flavour Name!'
                    except:
                        print 'A problem was encountered while trying to get GW Version info.'

            if self.gw_info['pfx_enabled'] == None:
                if 'PFXEnabled' in line:
                    self.gw_info['pfx_enabled'] = True if 'true' in line else False

            if self.gw_info['token_enabled'] == None:
                if 'TokenEnabled' in line:
                    self.gw_info['token_enabled'] = True if 'true' in line else False

    def gw_info_lookup(self, directory):
        self.setUpClass()
        self.get_ip_address(directory)
        self.create_price_order_server_logfiles_list(directory)
        try:
            self.price_order_server_logfiles
            self.get_details(directory)
            return self.gw_info
        except:
            print 'ERROR!! Logfile Zip appears to be collected from a non-Gateway machine!'
            return None