#!/usr/bin/python3
import click
import os
import tld
import requests as r
from tld.utils import update_tld_names
import dns.resolver
from datetime import datetime
import time
import sys

'''
Domain Scanner


Created by Faustino
'''


METHODS = (
    "create_dir","dirList", " urlStatus","getDomainName",
    "getInfo", "getMX", "getCN"
)


methods_counter = 0
update_tld_names()
Scanner=""
#click.echo(click.style(("    {}".format(code)),fg='green', bold=True))

class DNScanner:



    def __init__(self, url):
        self.url = url
        self.domain = tld.get_fld(str(url))
        self.mxlist = []

    def start(self):

        print(len(METHODS))
        with click.progressbar(length=len(METHODS)) as bar:

            for items in METHODS:
                bar.update(1)
                time.sleep(0.25)

            self.urlStatus()
            self.getDomainName()




    # region DirCreate
    # -----------CREATE DIRECTORIES-----------#
    def create_dir(directory):

        """
            Check if dir x is created
            """
        try:
            if not os.path.exists(directory):
                os.makedirs(directory)
        except Exception as e:
            click.echo(click.style((" Error: {}\n ".format(e)), fg='red', bold=True))
            click.echo(click.style(("Can´t create directories! {}".format(e)), fg='green', bold=True))
            print("They need to be created to save your results")
            directory.dirList()
        else:
            print("Directories already created")

    def dirList(self):
        '''
            List of dirs that need to create
            '''


        DNScanner.create_dir('Discovers')

        pass

    def writeFile(path, data):
        f = open(path, 'w')
        f.write(data)
        f.close()

    # endregion

    # region DomainCheck
    # -----------DOMAIN -----------#

    def urlStatus(self):
        '''
            This method check if domain is up
            '''


        url = self.url
        url = "https://www." + url
        code = r.get(url).status_code
        try:
            if code == 200:
                #if up then run all functions
                click.echo(click.style(("\nSite  Found! Code {}".format(code)),fg='green', bold=True))
                self.url = url

        except Exception as e:
            print("Error: {}".format(e))
            click.echo(click.style(("\nSite {}  Found! Code {} ".format(e,code)), fg='red', bold=True))

    def getDomainName(self):
        '''
              This method gets the domain and url
              '''


        url = self.url
        domain = self.domain
        print("Domain: " + domain)
        try:
            self.getInfo()
        except Exception as e:
            click.echo(click.style(("\nError: {}".format(e)), fg='red', bold=True))

        print("\nURL " + url)

    def getInfo(self):
        '''
              This  method gets the ip
              '''


        try:
            result = dns.resolver.resolve(self.domain, 'A')
            for ipval in result:
                click.echo(click.style(("\nIP {}".format(ipval)), fg='blue', bold=True))


        except Exception as e:
            click.echo(click.style(("\Cant resolve IP! Code {}".format(e)), fg='red', bold=True))

    def getMX(self):
        '''
                 This is method gets the MX records from the domain

                 '''

        mxlist = []

        result = dns.resolver.resolve(self.domain, 'MX')
        click.echo(click.style("#----MX RECORD-----#"))
        for data in result:
            mxlist.append(str(data))
        print("\nTotal MX Records: {} ".format(len(mxlist)))
        for item in mxlist:
           print(item)

    def getCN(self):
        '''
                 This is method gets CN records from the domain
                 '''

        result = dns.resolver.resolve(self.domain, 'CNAME')
        for cnameval in result:
            print(' cname target address:', cnameval.name)

    def output(self):
        # now = datetime.now()
        #current_time = now.strftime("%H-%M-%S")
        #te = current_time
        # print("Current Time =", current_time)
        CurrentDate =  datetime.today().strftime("%d-%b-%Y_%H-%M-%S")
        saveName = 'DNScanner-' + str(CurrentDate) + '.txt'
        open(r'Discovers/'+str(CurrentDate)+'.txt',"w")
        # os.rename(r'file.txt', r'DNScanner-' + str(CurrentDate) + '.txt')

        #os.rename(r'Discovers/files.txt', r'DNScanner-' + str(CurrentDate) + '.txt')



        #sys.stdout(open(r'DNScanner-'+str(hold_time)+'.txt'))

        sys.stdout = open(r"Discovers/{}".format(saveName)+".txt", 'a')
        # ("Discovers/DNS-Scan - " + time.ctime(),'a+')


    # endregion




def main():
    # input("Insert Url (example.com): ")
    DNScanner.urlStatus()
    DNScanner.getDomainName()
    # DNScanner.getRecords(url="google.com")
    pass


if __name__ == '__main__':
    Scanner = DNScanner("google.com")
    Scanner.getInfo()
    main()
