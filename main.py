#!/usr/bin/env python3
import click
import pandas as pd
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
from supplychain_check import sbom_digest
from supplychain_check import npm_repo_query
from supplychain_check import pypi_repo_query
from supplychain_check import composer_repo_query
from supplychain_check import nuget_repo_query

colorama_init()

@click.command()
@click.argument('file', type=click.Path(exists=True), required=1)
@click.option('--check', help='This option will check all packages if are vulnerable the Dependency Confusion attack.', required=True, is_flag=True)
@click.option('--output', help='Generate report output. (Default result.xlsx)', required=False, default='result.xlsx')
def args(file, check, output):
    pkgs = process(file)
    check_confusion(check, pkgs, output)

def process(file):
    try:
        sbom = sbom_digest(file)
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Processed SBOM file {Fore.GREEN}%s" %file)
        return sbom.process()
    except:
        print(f"{Fore.RED}[-] {Style.RESET_ALL}ERROR to process SBOM file {Fore.RED}%s" %file)
        exit()

def check_confusion(check, pkgs, output):
    print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Verifing packages... Wait...")
    if check == True:
        npm = npm_repo_query()
        pypi = pypi_repo_query()
        composer = composer_repo_query()
        nuget = nuget_repo_query()
        pkgs = npm.query_all_pkgs(pkgs)
        pkgs = pypi.query_all_pkgs(pkgs)
        pkgs = composer.query_all_pkgs(pkgs)
        pkgs = nuget.query_all_pkgs(pkgs)
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Verified packages, creating report...")
        df = pd.DataFrame(pkgs)
        # print(df)
        df.to_excel(output, index=False)

if __name__ == "__main__":
    try:
        args()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[#] {Style.RESET_ALL}Exiting...")
