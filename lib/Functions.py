from sys import stdin
from socket import socket
from ssl import create_default_context
from termcolor import colored

from lib.PathFunctions import PathFunction
from lib.Globals import ColorObj

def banner():
    banner = '\x1b[5m\x1b[1m\x1b[40m\x1b[31m   ______          __           \n  / ____/__  _____/ /____  _  __\n / /   / _ \\/ ___/ __/ _ \\| |/_/\n/ /___/  __/ /  / /_/  __/>  <  \n\\____/\\___/_/   \\__/\\___/_/|_|  \n                                \n\x1b[0m'
    print(banner)
    print(colored('Organization and Domain Extractor', color='red', attrs=['bold']))

def starter(argv):
    if argv.banner:
        banner()
        exit(0)
    if argv.output_directory:
        if not argv.domain:
            print("{} Output directory specified but not domain".format(ColorObj.bad))
            exit()
    if not argv.wordlist:
        if not argv.domain:
            if not argv.stdin:
                print("{} Use --help".format(ColorObj.bad))
                exit()
            else:
                stdinarray = stdin.read().split('\n')
                return [line.rstrip('\n').strip(' ') for line in stdinarray if line]
        else:
            return [argv.domain.strip(' ')]
    else:
        return [line.rstrip('\n') for line in open(argv.wordlist) if line]


def get_cert_data(hostname: str) -> tuple:
    ctx = create_default_context()
    with ctx.wrap_socket(socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        cert = s.getpeercert()
    subject = dict(x[0] for x in cert['subject'])
    issued_to = subject
    org, common = issued_to['organizationName'], issued_to['commonName']
    print(f"{ColorObj.good} Found {common}, {org}", end="\n")
    return common, org

def write_output(filename, orgs, commons, filepath=None) -> tuple:
    path_fn = PathFunction()
    if filepath:
        output_file = open(path_fn.slasher(filepath) + filename + '.certex', 'a')
    else:
        output_file = open(filename, 'a')
    for org in orgs:
        output_file.write(org)
        output_file.write('\n')
    for common in commons:
        output_file.write(common + '\n')
        output_file.close()
