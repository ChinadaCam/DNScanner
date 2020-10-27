#!/usr/bin/python3
import click

'''
Domain Scanner


Created by Faustino
'''

import os
import tld
import requests as r
from tld.utils import update_tld_names
import dns.resolver

update_tld_names()
Scanner=""
#click.echo(click.style(("    {}".format(code)),fg='green', bold=True))


class DNScanner:
    def __init__(self, url):
        self.url = url
        self.domain = tld.get_fld(str(url))

    # region DirCreate
    # -----------CREATE DIRECTORIES-----------#
    def create_dir(directory):
        # check if dir  exists, if not creat it
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
        except Exception as e:
            click.echo(click.style((" Error: {}\n ".format(e)), fg='red', bold=True))
            click.echo(click.style(("Can´t create directories! {}".format(e)), fg='green', bold=True))

            directory.dirList()
        else:
            print("Can´t create directories")
            print("They need to be created to save your results")

    def dirList(self):
        # list of dirs that need to create
        DNScanner.create_dir('Discovers')

        pass

    def writeFile(path, data):
        f = open(path, 'w')
        f.write(data)
        f.close()

    # endregion

    # region DomainCheck
    '-------CHECK IF DOMAIN IS UP-----#'

    def urlStatus(self):
        url = self.url
        url = "https://www." + url
        code = r.get(url).status_code
        try:
            if code == 200:
                #if up then run all functions
                click.echo(click.style(("\nSite  Found! Code {}".format(code)),fg='green', bold=True))

                self.url = url

                self.getDomainName()

            else:
                click.echo(click.style(("\nSite  Found! Code {}".format(code)),fg='red', bold=True))
        except Exception as e:
            print("Error: {}".format(e))
            click.echo(click.style(("\nSite {}  Found! Code {} ".format(e,code)), fg='red', bold=True))

    def getDomainName(self):
        url =  self.url
        domain = self.domain
        print("Domain: " + domain)
        try:
            self.getInfo()
        except Exception as e:
            click.echo(click.style(("\nError: {}".format(e)), fg='red', bold=True))

        print("\nURL " + url)


    def getInfo(self):

        try:
            result = dns.resolver.resolve(self.domain, 'A')
            for ipval in result:
                click.echo(click.style(("\nIP {}".format(ipval)), fg='blue', bold=True))


        except Exception as e:
            click.echo(click.style(("\Cant resolve IP! Code {}".format(e)), fg='red', bold=True))




    def getMX(self):
        result = dns.resolver.resolve(self.domain, 'MX')
        for exdata in result:
            print(' MX Record:', exdata)

    def getCN(self):

        result = dns.resolver.resolve(self.domain, 'CNAME')
        for cnameval in result:
            print(' cname target address:', cnameval.name)


    # endregion




def main():
    # input("Insert Url (example.com): ")
    DNScanner.urlStatus()
    DNScanner.getDomainName()
    # DNScanner.getRecords(url="google.com")

    Scanner.getDomainName()
    Scanner.urlStatus()

    pass


if __name__ == '__main__':
    Scanner = DNScanner("google.com")
    Scanner.getInfo()
    main()
