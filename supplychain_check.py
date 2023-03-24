import requests
import json
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import xmltodict

colorama_init()

class sbom_digest:
    def __init__(self, filename) -> None:
        with open(filename, 'r') as file:
            self.sbom = json.load(file)
    
    def process(self):
        pkgs = []
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Detected {Fore.BLUE}%i {Style.RESET_ALL}Packages" %len(self.sbom['components']))
        for num in range(0,len(self.sbom['components'])):
            try:
                tmp = {
                    "type": self.sbom['components'][num]['purl'].split(':', 1)[0],
                    "repo": self.sbom['components'][num]['purl'].split(':', 1)[1].split('/', 1)[0],
                    "pkg_name": self.sbom['components'][num]['name'],
                    "version": self.sbom['components'][num]['version'],
                    "vulnerableConfusionDependency": False
                }
            except KeyError:
                tmp = None

            if tmp != None:
                pkgs.append(tmp)
        self.all_pkgs = pkgs
        return self.all_pkgs
    
    
    def get_npm_pkgs(self):
        self.npm_packages = []
        for pkg in self.all_pkgs:
            if pkg['repo'] == 'npm':
                self.npm_packages.append(pkg)
        return self.npm_packages
class composer_repo_query:
    def __init__(self) -> None:
        self.repo_url = 'https://repo.packagist.org/p2'

    def query_pkg(self, pkg_name):
        response = requests.get('%s/%s.json' %(self.repo_url, pkg_name))
        response_json = json.loads(response.content)
        try:
            if response_json == "404 not found, no packages here":
                response_json = {
                    "error": "Not found"
                }
        except:
            pass
        return response_json
    
    def query_all_pkgs(self, pkgs):
        list_pkgs = []
        count = 0
        for pkg in pkgs:
            if pkg['repo'] == 'composer':
                count+=1
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Detected {Fore.BLUE}%i {Style.RESET_ALL}Packages Type COMPOSER Repo" %count)
        for pkg in pkgs:
            if pkg['repo'] == 'composer':
                consult = self.query_pkg(pkg['pkg_name'])
                try:
                    if consult['error'] == "Not found":
                        print(f"{Fore.RED} [-] {Style.RESET_ALL}Package is vulnerable {Fore.RED}%s:%s" %(pkg['repo'],pkg['pkg_name']))
                        pkg['vulnerableConfusionDependency'] = True
                except:
                    print(f"{Fore.BLUE} [*] {Style.RESET_ALL}Check package {Fore.GREEN}%s{Style.RESET_ALL} in repo {Fore.GREEN}%s" %(pkg['pkg_name'],pkg['repo']))
                    pkg['vulnerableConfusionDependency'] = False
            list_pkgs.append(pkg)
        return list_pkgs
        
class nuget_repo_query:
    def __init__(self) -> None:
        self.repo_url = 'https://api.nuget.org/v3-flatcontainer'

    def query_pkg(self, pkg_name):
        response = requests.get('%s/%s/index.json' %(self.repo_url, pkg_name))
        try:
            response_json = xmltodict.parse(response.content)
        except:
            response_json = json.loads(response.content)
        try:
            if response_json['Error']['Code'] == "BlobNotFound":
                response_json = {
                    "error": "Not found"
                }
        except:
            pass
        return response_json
    
    def query_all_pkgs(self, pkgs):
        list_pkgs = []
        count = 0
        for pkg in pkgs:
            if pkg['repo'] == 'nuget':
                count+=1
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Detected {Fore.BLUE}%i {Style.RESET_ALL}Packages Type NUGET Repo" %count)
        for pkg in pkgs:
            if pkg['repo'] == 'nuget':
                consult = self.query_pkg(pkg['pkg_name'])
                try:
                    if consult['error'] == "Not found":
                        print(f"{Fore.RED} [-] {Style.RESET_ALL}Package is vulnerable {Fore.RED}%s" %pkg['pkg_name'])
                        pkg['vulnerableConfusionDependency'] = True
                except:
                    print(f"{Fore.BLUE} [*] {Style.RESET_ALL}Check package {Fore.GREEN}%s{Style.RESET_ALL} in repo {Fore.GREEN}%s" %(pkg['pkg_name'],pkg['repo']))
                    pkg['vulnerableConfusionDependency'] = False
            list_pkgs.append(pkg)
        return list_pkgs
    
class composer_repo_query:
    def __init__(self) -> None:
        self.repo_url = 'https://repo.packagist.org/p2'

    def query_pkg(self, pkg_name):
        response = requests.get('%s/%s.json' %(self.repo_url, pkg_name))
        response_json = json.loads(response.content)
        try:
            if response_json == "404 not found, no packages here":
                response_json = {
                    "error": "Not found"
                }
        except:
            pass
        return response_json
    
    def query_all_pkgs(self, pkgs):
        list_pkgs = []
        count = 0
        for pkg in pkgs:
            if pkg['repo'] == 'composer':
                count+=1
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Detected {Fore.BLUE}%i {Style.RESET_ALL}Packages Type COMPOSER Repo" %count)
        for pkg in pkgs:
            if pkg['repo'] == 'composer':
                consult = self.query_pkg(pkg['pkg_name'])
                try:
                    if consult['error'] == "Not found":
                        print(f"{Fore.RED} [-] {Style.RESET_ALL}Package is vulnerable {Fore.RED}%s:%s" %(pkg['repo'],pkg['pkg_name']))
                        pkg['vulnerableConfusionDependency'] = True
                except:
                    print(f"{Fore.BLUE} [*] {Style.RESET_ALL}Check package {Fore.GREEN}%s{Style.RESET_ALL} in repo {Fore.GREEN}%s" %(pkg['pkg_name'],pkg['repo']))
                    pkg['vulnerableConfusionDependency'] = False
            list_pkgs.append(pkg)
        return list_pkgs
    
class pypi_repo_query:
    def __init__(self) -> None:
        self.repo_url = 'https://pypi.org/pypi'
        self.headers = 'Accept: application/json'
    
    def query_pkg(self, pkg_name):
        response = requests.get('%s/%s/json' %(self.repo_url, pkg_name))
        response_json = json.loads(response.content)
        try:
            if response_json['message'] == "Not Found":
                response_json = {
                    "error": "Not found"
                }
        except:
            pass
        return response_json
    
    def query_all_pkgs(self, pkgs):
        list_pkgs = []
        count = 0
        for pkg in pkgs:
            if pkg['repo'] == 'pypi':
                count+=1
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Detected {Fore.BLUE}%i {Style.RESET_ALL}Packages Type PYPI Repo" %count)
        for pkg in pkgs:
            if pkg['repo'] == 'pypi':
                consult = self.query_pkg(pkg['pkg_name'])
                try:
                    if consult['error'] == "Not found":
                        print(f"{Fore.RED} [-] {Style.RESET_ALL}Package is vulnerable {Fore.RED}%s" %pkg['pkg_name'])
                        pkg['vulnerableConfusionDependency'] = True
                except:
                    print(f"{Fore.BLUE} [*] {Style.RESET_ALL}Check package {Fore.GREEN}%s{Style.RESET_ALL} in repo {Fore.GREEN}%s" %(pkg['pkg_name'],pkg['repo']))
                    pkg['vulnerableConfusionDependency'] = False
            list_pkgs.append(pkg)
        return list_pkgs

class npm_repo_query:
    def __init__(self) -> None:
        self.repo_url = 'https://registry.npmjs.org'

    def query_pkg(self, pkg_name):
        response = requests.get('%s/%s' %(self.repo_url, pkg_name))
        response_json = json.loads(response.content)
        return response_json
    
    def query_pkg_by_version(self, pkg_name, pkg_version):
        response = requests.get('%s/%s/%s' %(self.repo_url, pkg_name, pkg_version))
        try:
            response_json = json.loads(response.content)
        except:
            response_json = {}
        
        try:
            if response_json.split(':', 1)[0] == 'version not found':
                response_json = {
                    "error": "Not found"
                }
        except:
            pass
        return response_json

    def query_all_pkgs(self, pkgs):
        list_pkgs = []
        count = 0
        for pkg in pkgs:
            if pkg['repo'] == 'npm':
                count+=1
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Detected {Fore.BLUE}%i {Style.RESET_ALL}Packages Type NPM Repo" %count)
        for pkg in pkgs:
            if pkg['repo'] == 'npm':
                consult = self.query_pkg(pkg['pkg_name'])
                try:
                    if consult['error'] == "Not found":
                        print(f"{Fore.RED} [-] {Style.RESET_ALL}Package is vulnerable {Fore.RED}%s" %pkg['pkg_name'])
                        pkg['vulnerableConfusionDependency'] = True
                except:
                    print(f"{Fore.BLUE} [*] {Style.RESET_ALL}Check package {Fore.GREEN}%s{Style.RESET_ALL} in repo {Fore.GREEN}%s" %(pkg['pkg_name'],pkg['repo']))
                    pkg['vulnerableConfusionDependency'] = False
            list_pkgs.append(pkg)
        return list_pkgs

if __name__ == "__main__":
    # sbom = sbom_digest()
    # sbom.process()
    nuget = nuget_repo_query()
    nuget_package = nuget.query_pkg('BouncyCassstle')
    print(nuget_package)