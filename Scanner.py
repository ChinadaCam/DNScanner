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

update_tld_names()
METHODS = (
    "create_dir","dirList", " urlStatus","getDomainName",
    "getInfo", "getMX", "getCN","output"
)

path=''
Scanner=""


class DNScanner:



    def __init__(self, url):
        self.url = url
        self.domain = tld.get_fld(str(url))
        self.mxlist = []
        self.CurrentDate = datetime.today().strftime("%d-%b-%Y_%H-%M-%S") #for files
        self.formatedDate = datetime.today().strftime("%d/%b/%Y %H:%M:%S") #for logs
        self.savesys = sys.stdout
        self.path = ''


    def start(self):
        '''
            Starts the program
            '''


        click.secho("#-----Initial Process -----#",color="blue")
        click.secho("Process started at {}".format(self.formatedDate))

        # print(len(METHODS))
        with click.progressbar(length=len(METHODS)) as bar:

            for items in METHODS:
                bar.update(1)
                time.sleep(0.4)
            self.urlStatus()
            self.getDomainName()

        #time.sleep(1)



# region DirCreate
    # -----------CREATE DIRECTORIES-----------#
    def create_dir(directory):
        """
            Check if dir x is created
            """

        try:
            click.secho("Checking if {} directory is created.".format(directory), fg='blue', bold=True)
            if not os.path.exists(directory):
                os.makedirs(directory)
                click.secho("Directory {} was created.".format(directory), fg='green', bold=True)
            else:
                click.secho("Directory {} already exists.".format(directory), fg="bright_yellow", bold=True)

            print("\n")
        except Exception as e:
            click.echo(click.style(("[!]  Error: {}\n ".format(e)), fg='red', bold=True))
            click.echo(click.style(("[!]  Can´t create directories! They need to be created to save your results! \n Error:{}".format(e)), fg='yellow', bold=True))
            directory.dirList()


    def dirList(self,add):
        '''
            List of dirs that need to create
            '''
        
        #Predefine your dirs here
        self.list = ['Discovers']
        
        self.add = add
        
        self.list.append(add)
        
        for item in range(len(self.list)):
            DNScanner.create_dir(self.list[item])

        pass

# endregion

# region DomainCheck
    # -----------DOMAIN -----------#

    def urlStatus(self):
        '''
            This method check if domain is up
            '''


        url = self.url
        url = "https://www." + url
        code= ""
        try:
            code = r.get(url).status_code
            if code == 200:
                #if up then run all functions
                click.echo(click.style(("\nSite  Found! Code {}".format(code)),fg='green', bold=True))
                self.url = url

        except Exception as e:
            click.secho("\n\n\The domain doesnt exist! Please insert a valid domain  ",fg='red',bold=True)

    def getDomainName(self):
        '''
              This method gets the domain and url
              '''

        try:
            url = self.url
            domain = self.domain
            print("\nURL " + url)
            print("Domain=  {} | {} ".format(self.domain))
            self.getInfo()
        except Exception as e:
            click.echo(click.style(("\nError: {}".format(e)), fg='red', bold=True))

    def getInfo(self):
        '''
              This  method gets the ip
              '''

        try:
            result = dns.resolver.resolve(self.domain, 'A')
            for ipval in result:
                click.echo(click.style(("IP {}".format(ipval)), fg='blue', bold=True))


        except Exception as e:
            click.echo(click.style(("\Cant resolve IP! Error: {}".format(e)), fg='red', bold=True))

    def getMX(self):
        '''
                 This is method gets the mail exchanger records from the domain

                 '''

        mxlist = []
        try:
            result = dns.resolver.resolve(self.domain, 'MX')
            click.echo(click.style("\n#-----MX RECORDS PROCESS-----#"))
            click.secho("Process started at {}".format(self.formatedDate))

            #get data from result
            for data in result:
                mxlist.append(str(data))
            print("\nTotal MX Records: {}   \n".format(len(mxlist)))
            i = 1
            for item in mxlist:
                print("({}) | {}".format(i,item))
                i += 1
        except Exception as e:
            click.echo(click.style(("\Cant resolve MX Records! Error: {}".format(e)), fg='red', bold=True))
            time.sleep(1)

    def getCN(self):
        '''
                 This is method gets CN records from the domain
                 '''
        try:
            result = dns.resolver.resolve(self.domain, 'CNAME')
            for cnameval in result:
                print(' cname target address:', cnameval.name)
        except Exception as e:
            click.secho("\Cant resolve CN Records! Error: {}".format(e), fg='red', bold=True)
    # endregion

    def output(self,path):
        '''
            Save outputs to a file with the current date and time
            '''

        #check if path is created
        self.dirList(path)

        time.sleep(0.2)
        click.secho("\n [*] Outputting to {}, just wait a bit".format(self.path), fg='yellow')

        saveName = 'DNScanner-' + str(self.CurrentDate) + '.txt'
        open(r'{}/'.format(path) + str(saveName) + '.txt', "w")
        self.path = path

        sys.stdout = open(r'{}/'.format(path) + str(saveName) + '.txt', "a")




if __name__ == '__main__':

    #Scanner = DNScanner("example.com")
    #Scanner.output('TestDir')
    #Scanner.getCN("mail.google.com")
    pass
