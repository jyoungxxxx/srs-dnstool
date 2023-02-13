# Prog: SRS-DNS-Tool
# Description: DNS Domain Tool (for Godaddy)
# Author: Josh Young
# Date: 6-8-2021
#
# Name:
#   Domain registrar automation tool
# Synopsis:
#   srs-dnstool --version
#   srs-dnstool [-h, --help]
#   srs-dnstool [-v] [-t <choice>] fqdn [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
#   srs-dnstool [-v] [-t <choice>] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
#   srs-dnstool [-v] [-t <choice>] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
#   srs-dnstool [-v] [-t <choice>] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
#   srs-dnstool [-v] [-t <choice>] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
#
# Descriptions:
#   -t <choice>      [ Transfer | Create | Update | Delete ]
#   -i               <csv_import>
#   -x               Transfer between accounts for the same registrar
#   -b               Backup domain DNS records
#   -l               Toggle Domain lock/unlock
#   -c               Request an auth code from the registrar
#   -o <email>       Set the admin email for a specified domain
#   -h, --help       show this help message and exit
#   -v <choice>      Set verbose or debugging. [non-verbose,verbose,debug], default:non-verbose
#   [-V,--version]   Show program information / version number and exit
#   --ip IP          DNS Address (defaults to public WAN address from https://checkip.amazonaws.com/)
#   --key KEY        GoDaddy production key
#   --secret SECRET  GoDaddy production secret
#   --ttl TTL        DNS TTL.
#   --force          force update of GoDaddy DNS record even if DNS query indicates that record is already correct
#
# [Modules]
import sys, csv, argparse, socket, json, urllib
from re import search

# [Global Variables]
global transfer_data
global create_data
global update_data
global remove_data

# Program details
prog = 'SRS-DNS-Tool',
version = '0.1'
description = 'Domain registrar automation tool'

# Message strings
msg_help = '''
 Name:
   Domain registrar automation tool
 Synopsis:
   srs-dnstool --version
   srs-dnstool [-h, --help]
   srs-dnstool [-v] [-t mode] fqdn [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
   srs-dnstool [-v] [-t mode] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
   srs-dnstool [-v] [-t mode] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
   srs-dnstool [-v] [-t mode] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]
   srs-dnstool [-v] [-t mode] fqdn | record | [--ip] [-i csvfile.txt] [--secret SECRET] [--ttl TTL] | [--force]

 Descriptions:
   -t <choice>      [ Transfer | Create | Update | Delete ]
   -i               <csv_import>
   -x               Transfer between accounts for the same registrar
   -b               Backup domain DNS records
   -l               Toggle Domain lock
   -c               Request an auth code from the registrar
   -o <email>       Set the admin email for a specified domain               
   -h, --help       show this help message and exit
   -v <choice>      Set verbose or debugging. [non-verbose,verbose,debug], default:non-verbose
   [-V,--version]   Show program information / version number and exit
   --ip IP          DNS Address (defaults to public WAN address from https://checkip.amazonaws.com/)
   --key KEY        GoDaddy production key
   --secret SECRET  GoDaddy production secret
   --ttl TTL        DNS TTL.
   --force          force update of GoDaddy DNS record even if DNS query indicates that record is already correct
'''

# Args
parser = argparse.ArgumentParser(
    prog='SRS-DNS-Tool',
    description='Domain registrar automation tool'
)

# parser.add_argument('-h', '--help', help='{msg_help}')
parser.add_argument('-v', choices=['non-verbose', 'verbose', 'debug'], default='non-verbose')
parser.add_argument('-V', '--version', action='version',
                    version='{} {}'.format(prog, version))
parser.add_argument('-t', choices=['Transfer', 'Create', 'Update', 'Remove'], required=True,
                    help='-t mode [ Transfer | Create | Update | Remove ]'
                         'transfer - Transfers DNS Domain registrars to specified DNS Registrar service' 
                         'create - Creates DNS Records and submits them to a specified DNS Registrar service' 
                         'update - Update DNS records for a specified DNS Registrar service' 
                         'remove - Removes DNS records from a specified DNS Registrar service')
parser.add_argument('-b', type=str, name='backup', default='', help='Backup domain records in case of loss of data \
                    during transfers or modifications.')
parser.add_argument('-d', type=str, default='', help='Transfer between accounts.')
parser.add_argument('-o', type=str, default='', help='Set the admin email for a specified domain')
parser.add_argument('-l', type=str, default='', help='Domain lock toggle')
parser.add_argument('-c', type=str, default='', help='Request auth code from registrar.')
parser.add_argument('fqdn', help='DNS fully-qualified host name with an A record.  If the hostname consists \
                    of only a domain name (i.e., it contains only one period), the record for @ is updated.')
parser.add_argument('--ip', type=str, default=None,
                    help='IPv4 address to write to DNS record (defaults to public WAN address from \
                    https://checkip.amazonaws.com/)')
parser.add_argument('-i', nargs='?', required=True, type=argparse.FileType('r'), help='Process CSV file \
                    containing domain data.')
parser.add_argument('--key', type=str, default='',
                    help='GoDaddy production key')
parser.add_argument('--secret', type=str, default='',
                    help='GoDaddy production secret')
parser.add_argument('--ttl', type=int, default=3600,
                    help='DNS TTL.')
parser.add_argument('--force', type=bool, default=False,
                    help='force update of GoDaddy DNS record even if DNS query indicates \
                    that record is already correct.')
args = parser.parse_args()

# [Global Variables]

# Dictionaries
args_data = {
    "verbose_debug": args.v,
    "tool_mode": args.t,
    "acct_xfer": args.d,
    "backup_domain": args.b,
    "request_auth_code": args.c,
    "set_admin_email": args.o,
    "toggle_lock": args.l,
    "csv_import_file": args.i,
    "fqdn": args.fqdn,
    "ip_addr": args.ip,
    "api_key": args.key,
    "api_secret": args.secret,
    "dns_ttl": args.ttl,
    "dns_force_update": args.force
}

dns_tf_reqs = {
    "business_line": "",
    "registrar": "",
    "dns_record": "",
    "dns_type": "",
    "lock_status": "",
    "expiration": "",
    "auto_renew": "",
    "mail_enabled": "",
    "account_info": "",
    "consent": "",
    "contactAdmin": "",
    "period": "",
    "privacy": "",
    "renewAuto": "",
    "authcode": "",
}

# Functions
def main():
    # hostnames = args.fqdn
    # if search('create',args.t):
    #     print('testing if statement: success')
    # else:
    #     print('testing if statement: failed')
    #     #print('Missing mode argument which is required for the tool to function.')

    print(args_data['verbose_debug'])
    print(args_data['tool_mode'])
    print(args_data['acct_xfer'])
    print(args_data['backup_data'])
    print(args_data['verbose_debug'])
    print(args_data['tool_mode'])
    print(args_data['acct_xfer'])
    print(args_data['backup_domain'])
    print(args_data['request_auth_code'])
    print(args_data['set_admin_email'])
    print(args_data['toggle_lock'])
    print(args_data['csv_import_file'])
    print(args_data['fqdn'])
    print(args_data['ip_addr'])
    print(args_data['api_key'])
    print(args_data['api_secret'])
    print(args_data['dns_ttl'])
    print(args_data['dns_force_update'])

    transfer_import(csvfile_import)
    transfer_processdata(transfer_data)
    create_import(csvfile_import)
    create_processdata(csvfile_data)

def transfer_import(csvfile_import):
    with open(csvfile_import, newline='') as f_open:
        csv_import = csv.DictReader(f_open)
    try:
        for row in csv_import:
            print(row['Registrar Account'], row['Domain Name'], row['New Domain'], row['Status'],
                  row['Expiration Date'], row['Auto-renew'], row['Privacy'], row['Lock'],
                  row['Main Enabled'])

            transfer_processdata += (row['Registrar Account'], row['Domain Name'], row['New Domain'], row['Status'],
                  row['Expiration Date'], row['Auto-renew'], row['Privacy'], row['Lock'],
                  row['Main Enabled'])
    except csv.Error as f_err:
        sys.exit('file {}, line {}:'.format(filename, csvfile_import.line_num, f_err))


def transfer_processdata(transfer_data):
    with open(csvfile_export, 'w', newline='') as f_open:
        fields = ['Business Line','Registrar Account','Domain Name','Status','Expiration Date','Auto-Renew']
        csv_export = csv.DictWriter(f_open, fieldnames=fields)
    try:
        csv_export.writeheader()

    except csv.Error as f_err:
        sys.exit('file {}, line {}:'.format(filename, csv_export.line_num, f_err))


def create_import(csvfile_import):
    with open(csvfile_import, newline='') as f_open:
        csv_import = csv.DictReader(f_open)
    try:
        for row in csv_import:
            print(row['Registrar Account'], row['Domain Name'], row['New Domain'], row['Status'],
                  row['Expiration Date'], row['Auto-renew'], row['Privacy'], row['Lock'],
                  row['Main Enabled'])

            create_data += (row['Registrar Account'], row['Domain Name'], row['New Domain'], row['Status'],
                  row['Expiration Date'], row['Auto-renew'], row['Privacy'], row['Lock'],
                  row['Main Enabled'])

    except csv.Error as f_err:
        sys.exit('file {}, line {}:'.format(filename, extdns_read.line_num, f_err))
# Main process


# print(args.accumulate(args.integers))

def create_processdata():
    hostnames = args.hostname.split('.')
    if len(hostnames) < 2:
        msg = 'Hostname "{}" is not a fully-qualified host name of form "HOST.DOMAIN.TOP".'.format(args.hostname)
        raise Exception(msg)
    elif len(hostnames) < 3:
        hostnames.insert(0, '@')

    if not args.ip:
        try:
            with urlopen(Request("https://checkip.amazonaws.com/", headers={'User-Agent': 'Mozilla'})) as f:
                resp = f.read()
            if sys.version_info > (3,): resp = resp.decode('utf-8')
            args.ip = resp.strip()
        except URLError:
            msg = 'Unable to connect to URL https://checkip.amazonaws.com/.'
            raise Exception(msg)

    ipslist = args.ip.split(",")
    for ipsiter in ipslist:
        ips = ipsiter.split('.')
        if len(ips) != 4 or \
                not ips[0].isdigit() or not ips[1].isdigit() or not ips[2].isdigit() or not ips[3].isdigit() or \
                int(ips[0]) > 255 or int(ips[1]) > 255 or int(ips[2]) > 255 or int(ips[3]) > 255:
            msg = '"{}" is not valid IP address.'.format(ips)
            raise Exception(msg)

    if not args.force and len(ipslist) == 1:
        try:
            dnsaddr = socket.gethostbyname(args.hostname)
            if ipslist[0] == dnsaddr:
                msg = '{} already has IP address {}.'.format(args.hostname, dnsaddr)
                raise Exception(msg)
        except:
            pass

    url = 'https://api.godaddy.com/v1/domains/{}/records/A/{}'.format('.'.join(hostnames[1:]), hostnames[0])
    data = json.dumps([{"data": ip, "ttl": args.ttl, "name": hostnames[0], "type": "A"} for ip in ipslist])
    if sys.version_info > (3,):  data = data.encode('utf-8')
    req = Request(url, method='PUT', data=data)

    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")

    if args.key and args.secret:
        req.add_header("Authorization", "sso-key {}:{}".format(args.key, args.secret))

    try:
        with urlopen(req) as f:
            resp = f.read()
        if sys.version_info > (3,):  resp = resp.decode('utf-8')
        # resp = json.loads(resp)
    except HTTPError as e:
        if e.code == 400:
            msg = 'Unable to set IP address: GoDaddy API URL ({}) was malformed.'.format(req.full_url)
        elif e.code == 401:
            if args.key and args.secret:
                msg = '''Unable to set IP address: --key or --secret option incorrect.
Correct values can be obtained from from https://developer.godaddy.com/keys/ and are ideally placed in a % file.'''
            else:
                msg = '''Unable to set IP address: --key or --secret option missing.
Correct values can be obtained from from https://developer.godaddy.com/keys/ and are ideally placed in a % file.'''
        elif e.code == 403:
            msg = '''Unable to set IP address: customer identified by --key and --secret options denied permission.
Correct values can be obtained from from https://developer.godaddy.com/keys/ and are ideally placed in a % file.'''
        elif e.code == 404:
            msg = 'Unable to set IP address: {} not found at GoDaddy.'.format(args.hostname)
        elif e.code == 422:
            msg = 'Unable to set IP address: "{}" has invalid domain or lacks A record.'.format(args.hostname)
        elif e.code == 429:
            msg = 'Unable to set IP address: too many requests to GoDaddy within brief period.'
        elif e.code == 503:
            msg = 'Unable to set IP address: "{}" is unavailable.'.format(args.hostname)
        else:
            msg = 'Unable to set IP address: GoDaddy API failure because "{}".'.format(e.reason)
        raise Exception(msg)
    except URLError as e:
        msg = 'Unable to set IP address: GoDaddy API failure because "{}".'.format(e.reason)
        raise Exception(msg)

    print('IP address for {} set to {}.'.format(args.hostname, args.ip))
