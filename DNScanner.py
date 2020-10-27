import click
from Scanner import DNScanner

#Flags

@click.command()
@click.option('-d', '--domain', required=True, help="Set domain")
@click.option('-mx',default=False,type=click.Choice,required=False,help="Get NX Records")
type=click.Choice(['True','False'],case_sensitive=False)

def main(domain,mx):
    click.echo(click.style(('DNScanner made by Faustino'),fg='bright_white',bg='cyan'))
    Scanner = DNScanner(domain)
    Scanner.urlStatus()
    
    #Toggle mx
    if mx:
        Scanner.getMX()

if __name__ == '__main__':
    main()
