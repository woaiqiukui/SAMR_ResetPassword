
import opcode
import re
import sys
import logging
import argparse
from urllib import request

from impacket import version
from impacket import crypto, ntlm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples import logger
from impacket.dcerpc.v5 import transport, epm, samr

class RESETNTLM:
    def __init__(self, username, password, domain, options = None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__targetuser = options.user
        self.__targetserver = options.server
        self.__lmhash = ''
        self.__nthash = ''
        self.__targetIp = options.dc_ip
        self.__doKerberos = options.k
        self.__aeskey = options.aesKey
        self.__kdcHost = options.dc_host
        self.__new_passwd = options.new_pass

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

        if self.__doKerberos and options.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use -dc-host.")


    def init_samr(self):
        if self.__doKerberos:
            stringBinding = epm.hept_map(self.__kdcHost, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
        else:
            stringBinding = epm.hept_map(self.__targetIp, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(445)
        rpctransport.setRemoteHost(self.__targetIp)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aeskey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        self.run_reset(dce)
        
    def run_reset(self, dce):
        userHandle = None
        serverHandle = None
        domainHandle = None

        try:
            logging.info("Connecting to Server {}...".format(self.__targetserver))

            samrConnectRep = samr.hSamrConnect5(dce, '{}\x00'.format(self.__targetserver),
                                                   samr.SAM_SERVER_CONNECT | samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN)
            serverHandle = samrConnectRep['ServerHandle']

            logging.info("Enumerating domains on target server...")

            samrEnumDomainRep = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = samrEnumDomainRep['Buffer']['Buffer']

            # Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py#L444
            domainsWithoutBuiltin = list(filter(lambda x: x['Name'].lower() != 'builtin', domains))

            if len(domainsWithoutBuiltin) > 1:
                domain = list(filter(lambda x: x['Name'].lower() == self.__domain, domains))
                if len(domain) != 1:
                    logging.critical("This server provides multiple domains and '%s' isn't one of them.",
                                     self.__domain)
                    logging.critical("Available domain(s):")
                    for domain in domains:
                        logging.error(" * %s" % domain['Name'])
                    raise Exception()
                else:
                    selectedDomain = domain[0]['Name']
            else:
                selectedDomain = domainsWithoutBuiltin[0]['Name']
            logging.info("Select domain: {}".format(selectedDomain))

            samrLookupDomainRep = samr.hSamrLookupDomainInSamServer(dce, serverHandle, selectedDomain)
            domainSID = samrLookupDomainRep['DomainId']

            logging.info("Try to Open domain {}...".format(selectedDomain))

            try:
                samrOpenDomainRep = samr.hSamrOpenDomain(dce, serverHandle, samr.DOMAIN_LOOKUP, domainSID)
                domainHandle = samrOpenDomainRep['DomainHandle']
            except samr.DCERPCSessionError as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()

                logging.critical(str(e))
                exit(0)

            try:
                logging.info("Looking up user {}...".format(self.__targetuser))
                samrLookupNamesRep = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.__targetuser,))
                userRID = samrLookupNamesRep['RelativeIds']['Element'][0]
            except samr.DCERPCSessionError as e:
                if e.error_code == 0xc0000073:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.critical('There\'s no such user in present domain')
                exit(0)
                    

            try:
                logging.info("Open the handle to the user object...")
                samrOpenUserRep = samr.hSamrOpenUser(dce, domainHandle, samr.USER_FORCE_PASSWORD_CHANGE, userRID)
                userHandle = samrOpenUserRep['UserHandle']
            except samr.DCERPCSessionError as e:
                if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                logging.critical('No enough permission to reset the passwd')
                exit(0)

            try:
                resetPasswdStatus = samr.hSamrSetPasswordInternal4New(dce, userHandle, self.__new_passwd)
            except Exception as e:
                import traceback
                traceback.print_exc()
            if resetPasswdStatus['ErrorCode'] == 0:
                print('[+] Reset password success!')

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()

            logging.critical(str(e))
        finally:
            if userHandle is not None:
                samr.hSamrCloseHandle(dce, userHandle)
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if serverHandle is not None:
                samr.hSamrCloseHandle(dce, serverHandle)
            dce.disconnect() 

    def run(self):
            self.init_samr()


if __name__ == '__main__':
    
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Reset domain user's hash.")

    parser.add_argument('target', action='store', help='[domain/]username[:password] This user is '
                                                        'used to authenticate to DC.')
    
    parser.add_argument('-user', action='store', help='Target user you want to change its password.')
    parser.add_argument('-server', action='store', help='Target server\'s netbios name. If target '
                                                        'user is domain user, it should be DC.')
    parser.add_argument('-new-pass', action='store', help='New plain-text password for target user.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on account parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-dc-ip', action='store', metavar="ip", help='IP of the domain controller to use. '
                                                                    'Useful if you can\'t translate the FQDN.'
                                                                    'specified in the account parameter will be used')
    group.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller to use. '
                                                                            'If ommited, the domain part (FQDN) '
                                                                            'specified in the account parameter will be used')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = re.compile('(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?').match(
        options.target).groups('')

    # If you use kerberos tickets, the domain name here needs to
    # correspond to the domain name in the ticket. otherwise an
    # KDC_ERR_PREAUTH_FAILED error will occur.
    if domain is None or domain == '':
        logging.critical('Domain name should be specified, If you use '
                         'kerberos tickets, you need to specify "domain/:"')
        sys.exit(1)



    if options.user is None:
        logging.critical('Target username should be specified!')
        sys.exit(1)


    if options.new_pass is None and options.new_ntlm is None:
        logging.critical('Target user\'s new plain-text password or NTLM hash should be specified!')
        sys.exit(1)

    if options.dc_ip is None:
        logging.critical('Parameter -dc-ip should be specified!')
        sys.exit(1)

    executer = RESETNTLM(username, password, domain, options)
    try:
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)