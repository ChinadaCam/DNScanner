#!/usr/bin/python3
from logging import exception
import socket
import click
import os
import requests as r
from tld.utils import update_tld_names
import dns.resolver
from datetime import datetime
import time
import sys
import unittest
from ipwhois import IPWhois
import json

#import netaddr

# Domain Scanner
# Copyright (c) 2020-2023 @ Tiago Faustino
# All rights reserved.


update_tld_names()
METHODS = (
    "create_dir","dirList", " urlStatus","getDomainName",
    "getInfo","checkSubdomain", "getMX", "getNS", "getCN","output"
)

path=''
Scanner=""
stsave = sys.stdout


with click.progressbar(length=len(METHODS)) as bar:

    for items in METHODS:
        bar.update(2)
        time.sleep(0.01)


class DNScanner:



    def __init__(self, url):
        try:
            self.url = url
            self.domain = str(url)
            self.ip= socket.gethostbyname(self.domain)
            self.mxlist = []
            self.CurrentDate = datetime.today().strftime("%d-%b-%Y_%H-%M-%S") #for files
            self.formatedDate = datetime.today().strftime("%d/%b/%Y %H:%M:%S") #for logs
            self.savesys = sys.stdout
            self.outputpath = ''
            self.subdomainspath = ''
            self.subdomainbool = False

        except Exception as e:
            print(e)
        except socket.error as error:
            print(error)

    def start(self):
        '''
            Starts the program
            '''

        self.dirList('Others')

        click.secho("#-----Initial Process -----#",color="blue")
        click.secho("Process started at {}".format(self.formatedDate))
        self.logger(0,"Process started at {}".format(self.formatedDate))
        self.urlStatus()
        # print(len(METHODS))



        if self.subdomainbool:

                self.urlStatus()
                self.getDomainName()
                self.getSubdomains(self.subdomainspath)
                return


        self.getDomainName()

        #time.sleep(1)



# region DirCreate
    # -----------CREATE DIRECTORIES-----------#
    def create_dir(directory):
        """
            Check if dir x is created
            """

        try:
            #click.secho("Checking if {} directory is created.".format(directory), fg='blue', bold=True)
            if not os.path.exists(directory):
                os.makedirs(directory)
                click.secho("Directory {} was created.".format(directory), fg='green', bold=True)
            #else:
                #click.secho("Directory {} already exists.".format(directory), fg="bright_yellow", bold=True)

            #print("\n")
        except Exception as e:
            click.echo(click.style(("[!]  Error: {}\n ".format(e)), fg='red', bold=True))
            click.echo(click.style(("[!]  Can´t create directories! They need to be created to save your results! \n Error:{}".format(e)), fg='yellow', bold=True))



    def dirList(self,add):
        '''
            List of dirs that need to create
            '''
        
        #Predefine your dirs here
        self.list = ['DNScanner/Others','DNScanner/Others/Discovers','DNScanner/Others/wordlists','DNScanner/logs/']
        
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
            This method check if url and domain is up
            '''


        url = self.url
        url = "http://www."+url
        code= ""
        ip = self.ip
        #response = os.system("ping  " + ip)
        try:
            

            #check the ping response
            response = os.popen(f"ping -c 1 {ip}").read()
            if "Received = 4" in response:
                print(f"\nIP: {ip} -  Ping reachable ✅")
            else:
                print(f"\nIP: {ip} - Ping not reachable ❌")
          
            code = r.get(url).status_code

            if code == 200:
                #if up then run all functions
                click.echo(click.style(("\nSite  Found! Code {}".format(code)),fg='green', bold=True))
                self.url = url
            
              


        except Exception as e:
            click.secho(f"\n\n\The domain not found! Please insert a valid domain. \n{e}",fg='red',bold=True)
    
    def whoIs(self):
       
        click.secho("\n #------- WHOIS-------#\n")

        whois = IPWhois(self.ip)
        res = whois.lookup_whois() 
        data = json.dumps(res,sort_keys=True, indent=4) #.loads(res)
        rep = json.loads(data)

        for x in rep:

            if x == "nets":
                for y in rep["nets"]:
                    print(y)
        #print(f"Country: {rep['country']}")
        #print(f"{data}")
        print("\n Dns zone: "+whois.dns_zone)

    def whoIsJson(self):
        click.secho("\n #------- WHOIS JSON-------#\n")

        whois = IPWhois(self.ip)
        res = whois.lookup_whois()
        data = json.dumps(res, sort_keys=True, indent=4)  # .loads(res)

        print(data)

    def getGeo(self):
            'to-do'
            pass



    def getDomainName(self):
        '''
              This method check if host is up (domain/url), then runs getInfo()
              '''
        

        try:
            url = self.url
            domain = self.domain
            print("\nURL= "+ url)
            print("Domain= {} ".format(self.domain))
            self.getInfo()
        except Exception as e:
            click.echo(click.style(("\nError: {}".format(e)), fg='red', bold=True))

    def getInfo(self):
        '''
              This  method gets the ip
              '''

        try:
            result4 = dns.resolver.resolve(self.domain, 'A')
            result6 = dns.resolver.resolve(self.domain, 'AAAA')
            i = 0
            for ipval in result4:
                i+=1
                click.echo(click.style(("({}) IPV4 {}".format(i,ipval)), fg='blue', bold=True))

            for ipval in result6:
                i += 1
                click.echo(click.style(("({}) IPV6 {}".format(i, ipval)), fg='blue', bold=True))


        except Exception as e:
            click.echo(click.style(("\Cant resolve IP! Error: {}".format(e)), fg='red', bold=True))

    def getMX(self):
        '''
                 This is method gets the mail exchanger records from the domain

                 '''

        mxlist = []
        try:
            result = dns.resolver.resolve(self.domain, 'MX')
            click.echo(click.style("\n#------- MX RECORDS  -------#"))
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
        click.secho("\n #------- CANONICAL NAMES-------#\n")         
        try:
            result = dns.resolver.resolve(self.domain, 'CNAME')
            for cnameval in result:
                print(' cname target address:', cnameval.name)
        except Exception as e:
            click.secho("\Cant resolve CN Records! Error: {}".format(e), fg='red', bold=True)

    def getNS(self):
        '''
             This is method gets nameserver records from the domain
                 '''
        click.secho("\n #------- NAMESERVERS -------#\n")

        try:
            answers = dns.resolver.query(self.domain,'NS')
            for server in answers:
                print(f"{server.target}")
        except Exception as e:
            click.secho("\Cant resolve NS Records! Error: {}".format(e), fg='red', bold=True)
    
    def getSubdomains(self, path):
        '''
                  Check for subdomains
                   '''
        click.secho("\n #------- SUBDOMAINS -------#\n")
        click.secho("Process started at {}".format(self.formatedDate))
        self.subdomainspath = 'DNScanner\Others\wordlist'
        file = open(path, 'r')
        content = file.read()
        subdomains = content.splitlines()
        try:
            print("Discovered Domains:")
            for subdomain in subdomains:
                url = f'http://{subdomain}.{self.domain}'
                try:
                    r.get(url)
                except r.ConnectionError:
                    pass
                except KeyboardInterrupt as e:
                    sys.stdout = stsave
                    print('KeyboardInterrupt')
                    return "stopped"
                else:
                    print("\t",url)
        except KeyboardInterrupt as e:
            sys.stdout = stsave
            print('KeyboardInterrupt')
            sys.exit(0)
            pass


    
    

# endregion

    def output(self,path):
        '''
            Save outputs to a file with the current date and time
            '''

        try:
            #check if path is created
            self.dirList(path)

            time.sleep(0.2)
            click.secho("\n [*] Outputting to {}, just wait a bit".format(self.outputpath), fg='yellow')

            saveName = 'DNScanner-' + str(self.CurrentDate) + '.txt'
            open(r'{}/'.format(path) + str(saveName) + '.txt', "w")
            self.outputpath = path

            sys.stdout = open(r'{}/'.format(path) + str(saveName) + '.txt', "a")
        except KeyboardInterrupt as e:
            sys.stdout = stsave
            print('KeyboardInterrupt')
            sys.exit(0)



#region API's

    def logger(self,importance,text):
        '''
                    logger
                    '''
        saveName = 'ScanLog-' + str(self.CurrentDate)
        f = open('DNScanner/logs/' + str(saveName) + '.txt', "a")
        f.write(f"{importance} | {text}")



if __name__ == '__main__':

    #Scanner = DNScanner("example.com")
    #Scanner.output('TestDir')
    #Scanner.getCN("mail.google.com")
    pass
