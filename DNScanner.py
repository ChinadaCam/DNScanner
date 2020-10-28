import argparse
import time
from Scanner import DNScanner
from click import secho, pause
import sys


savesys = sys.stdout

# Flags
parser = argparse.ArgumentParser(description='\t Scan domains  https://github.com/ChinadaCam/DNScanner')
parser.add_argument('-d', '--domain', required=True, type=str, help='Set domain (example.com)')
parser.add_argument('-D', '--directory', const='Discovers',nargs='?', help='Define a directory to output.\n Default is Discovers')
parser.add_argument('-mx', '--mx', nargs='?', const='True' ,help='Show Mail Exanger Records (MX RECORDS)')
#parser.add_argument('-cn', '--cname', nargs='?', const='True' ,help='Show Canonical Name Records(CN Records)')
args = parser.parse_args()


def main():
    secho('------------------------------------------------')
    secho('\t DNScanner '
          '\n\tMade by Faustino'
          '\n  Project link: https://github.com/ChinadaCam/DNScanner ', fg='bright_white')
    secho('------------------------------------------------\n')
    Scanner = DNScanner(args.domain)
    #check if output is used
    if args.directory:
        Scanner.output(args.directory)

    Scanner.start()

    # Toggle mx
    if args.mx:
        Scanner.getMX()

    #if args.cname:
       #Scanner.getCN()

    sys.stdout = savesys
    secho("\n[+] Finished ", fg="green")




if __name__ == '__main__':
    main()
