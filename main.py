import click
from Scanner import DNScanner


@click.command()
@click.option('-d', '--domain', required=True, help="Set domain")
@click.option('-mx',default=False, type=bool, required=False, help="Get NX Records")
def main(domain,mx):
    click.echo(click.style(('Test'),fg='green',bg='red'))
    Scanner = DNScanner(domain)
    Scanner.urlStatus()

    if mx:
        Scanner.getMX()

if __name__ == '__main__':
    main()
