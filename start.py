import argparse
#from click import secho
import sys
from DNScanner.DNScanner import DNScanner

savesys = sys.stdout

# Flags
parser = argparse.ArgumentParser(description='\t Scan domains  https://github.com/ChinadaCam/DNScanner')
parser.add_argument('-d', '--domain', required=True, type=str, help='Set domain (example.com)')
parser.add_argument('-cS', '--checkSubdomains', const='Others\wordlists\subdomainlist.txt', nargs='?' , help='Check subdomains and give an output if founded. (Default path: Others\wordlists\10000-dnswords.txt) ')
parser.add_argument('-O', '--Output', const='Others\Discovers',nargs='?', help='Output to file.\n Default is Other/Discovers, change directory with --directory ')
parser.add_argument('-D', '--Directory', const='Others\Discovers',nargs='?', help='Define a directory to output.\n Default is Discovers')
parser.add_argument('-mx', '--mxrecords', nargs='?', const='True' ,help='Show Mail Exanger Records (MX RECORDS)')
parser.add_argument('-A', '--all', nargs='?', const='True' ,help='Run all parameters (output not included)')
parser.add_argument('-cn', '--cname', nargs='?', const='True' ,help='Show Canonical Name Records(CN Records)')
args = parser.parse_args()


def main():
    print('------------------------------------------------')
    print('\t DNScanner '
          '\n\tMade by Faustino'
          '\n  Project link: https://github.com/ChinadaCam/DNScanner ' )
    print('------------------------------------------------\n')
    Scanner = DNScanner(args.domain)





    if args.all:
        args.mxrecords = True
        Scanner.subdomainspath = 'DNScanner\Others\wordlists\subdomainlist.txt'
        Scanner.subdomainbool = True

        # check if output is used
    if args.Output:
        if args.Directory:
            Scanner.output(args.Directory)
        else:
            Scanner.output(args.Output)

    if args.checkSubdomains:
        Scanner.subdomainspath = args.checkSubdomains
        Scanner.subdomainbool = True

    Scanner.start()
    # Toggle mx
    if args.mxrecords:
        Scanner.getMX()







    #if args.cname:
       #Scanner.getCN()

    sys.stdout = savesys
    #secho("\n[+] Finished ", fg="green")
    print("\n[+] Finished ")



if __name__ == '__main__':
    main()
