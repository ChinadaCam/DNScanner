import click
from Scanner import DNScanner

'''@click.option(
    "-f",
    "--format",
    "output_format",
    type="txt",
    default="txt",
    help="Output format",
)'''

''' Falta adicionar flgas - output format, logs,proxy e mac changer
    Corrigir outputs
    Fix ao -o para nao ter de ter argumentos
    Ver CVE
'''

#Flags


@click.version_option(version='0.0.1')
@click.command()
@click.option('-d', '--domain', required=True, help="Set domain")
@click.option('-o','--output',required=False, help="Output to a file")
@click.option('-mx',type=click.Choice(['True','False'],case_sensitive=False),
              required=False,help="Get NX Records")



def main(domain,mx,output,*kwargs):

        click.echo(click.style(('DNScanner made by Faustino'),fg='bright_white'))
        Scanner = DNScanner(domain)
        if output:
            Scanner.output()

        Scanner.start()



        #Toggle mx
        if mx:
            Scanner.getMX()


        print("\n")

        click.pause()

if __name__ == '__main__':
    main()
