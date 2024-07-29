import asyncio
import aiohttp
from bs4 import BeautifulSoup
import ssl
import whois
from datetime import datetime
from urllib.parse import urlparse
import tldextract
from tld import get_tld
import aiodns
import cachetools
import socket
import time
from collections import Counter
import os
import argparse


RED = '\033[31m'
BRIGHT_RED = '\033[91m'
YELLOW = '\033[33m'
BRIGHT_YELLOW = '\033[93m'
ORANGE = '\033[38;5;208m'
WHITE = '\033[97m'
ENDC = '\033[0m'
BOLD = '\033[1m'

BLUE = '\033[34m'
PURPLE = '\033[35m'
GREEN = '\033[32m'

# Colored operators
INFO = f"{BLUE}[*]{ENDC}"
SUCCESS = f"{GREEN}[+]{ENDC}"
WARNING = f"{YELLOW}[!]{ENDC}"
ERROR = f"{RED}[-]{ENDC}"

# Initialize cache
domain_cache = cachetools.TTLCache(maxsize=10000, ttl=3600)  # Cache for 1 hour

def banner():
    print(f"""{BOLD}
          

    Developer: {PURPLE}@Stuub{ENDC} {BOLD}{YELLOW}|{ENDC}  {BOLD}Version: {PURPLE}1.0.0{ENDC} {BOLD}{YELLOW}|{ENDC}  {BOLD}GitHub: {PURPLE} https://github.com/Stuub{ENDC}{BOLD}
___________________________________________________________________________________________________________________________________________________________________________
{BRIGHT_RED}▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░  ▒ ░░   ▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░░░ ▒▒░ ▒ ░▒▓▒ ▒ ▒  ▒▒   ▓▒█░  ▒ ░░   ▒ ▒▓▒ ▒ ░{ENDC}
{ORANGE}░ ░▒  ░ ░ ░ ▒░  ░ ░░▒░ ░ ░   ▒   ▒▒ ░    ░    ░ ░▒  ░ ░ ░ ▒░  ░ ░░▒░ ░ ░   ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░░ ░▒  ░ ░ ░ ▒░  ░ ░░▒░ ░ ░   ▒   ▒▒ ░    ░    ░ ░▒  ░ ░{ENDC}
{YELLOW}░  ░  ░     ░   ░  ░░░ ░ ░   ░   ▒     ░      ░  ░  ░     ░   ░  ░░░ ░ ░   ░   ▒   ░  ░  ░   ░  ░░ ░   ░     ░░   ░ ░ ▒░  ░ ░░▒░ ░ ░   ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░  ░▒{ENDC}
{YELLOW}      ░      ░       ░           ░  ░               ░      ░       ░           ░  ░      ░   ░  ░  ░   ░  ░   ░ ░  ░  ░     ░   ░  ░░░ ░ ░   ░   ▒     ░      ░  ░  ░     ░{ENDC}
{BRIGHT_YELLOW}░      ░       ░           ░  ░               ░      ░       ░           ░  ░      ░   ░  ░  ░   ░  ░   ░     ░  ░░░ ░ ░   ░   ▒   ░  ░  ░   ░  ░░ ░   ░     ░░   ░{ENDC}                                                                                                                                                                                                                       

      {BOLD}*******                                                        *******                                                     *                              
    *       ***                                          *         *       ***                                                 **                               
   *         **                                         **        *         **                                                 **                               
   **        *                                          **        **        *                                                  **                               
    ***             ****    **   ****                 ********     ***             ****    **   ****                   ****    **                  ***  ****    
   ** ***          * ***  *  **    ***  *    ****    ********     ** ***          * ***  *  **    ***  *    ****      * **** * **  ***      ***     **** **** * 
    *** ***       *   ****   **     ****    * ***  *    **         *** ***       *   ****   **     ****    * ***  *  **  ****  ** * ***    * ***     **   ****  
      *** ***    **    **    **      **    *   ****     **           *** ***    **    **    **      **    *   ****  ****       ***   ***  *   ***    **         
        *** ***  **    **    **      **   **    **      **             *** ***  **    **    **      **   **    **     ***      **     ** **    ***   **         
          ** *** **    **    **      **   **    **      **               ** *** **    **    **      **   **    **       ***    **     ** ********    **         
           ** ** **    **    **      **   **    **      **                ** ** **    **    **      **   **    **         ***  **     ** *******     **         
            * *  **    **    **      **   **    **      **                 * *  **    **    **      **   **    **    ****  **  **     ** **          **         
  ***        *    *******     ******* **  **    **      **       ***        *    *******     ******* **  **    **   * **** *   **     ** ****    *   ***        
 *  *********      ******      *****   **  ***** **      **     *  *********      ******      *****   **  ***** **     ****    **     **  *******     ***       
*     *****            **                   ***   **           *     *****            **                   ***   **             **    **   *****                
*                      **                                      *                      **                                              *                         
 **                    **                                       **                    **                                             *                          
                        **                                                             **                                           *                           
                                {ENDC}
                                                                                                                                        
                                                                                                                                                             


          {ENDC}""")

async def aio_whois_query(domain):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f'https://www.whois.com/whois/{domain}', timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    if "No match for" in text or "NOT FOUND" in text:
                        return False
                    return True
        except:
            return None

async def resolve_domain(domain, resolver):
    try:
        result = await resolver.query(domain, 'A')
        return [r.host for r in result]
    except aiodns.error.DNSError:
        return False

async def check_domain(domain, resolver):
    if domain in domain_cache:
        return domain_cache[domain]

    whois_result = await aio_whois_query(domain)
    if whois_result is None:
        result = f"Error checking {domain}"
    elif whois_result:
        dns_result = await resolve_domain(domain, resolver)
        if dns_result:
            ips = ', '.join(dns_result)
            result = f"{domain} is registered and resolves to IP(s): {BOLD}{ips}{ENDC}"
        else:
            result = f"{domain} is registered but does not resolve to an IP"
    else:
        result = f"{domain} is not registered"

    domain_cache[domain] = result
    return result

def generate_typos(domain):
    tld = get_tld(f"http://{domain}", as_object=True)
    name = domain[:-(len(tld.tld) + 1)]  # remove TLD and dot
    typos = []
    
    # Common typos
    keyboards = {
        'qwerty': {
            'q': 'wa', 'w': 'qes', 'e': 'wrd', 'r': 'eft', 't': 'rgy',
            'y': 'thu', 'u': 'yij', 'i': 'uok', 'o': 'ipl', 'p': 'o',
            'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc', 'g': 'ftyhbv',
            'h': 'gyujnb', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
            'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
    }
    
    # Generate typos
    for i, c in enumerate(name):
        for adj in keyboards['qwerty'].get(c.lower(), ''):
            typos.append(name[:i] + adj + name[i+1:])
    
    # Omissions
    for i in range(len(name)):
        typos.append(name[:i] + name[i+1:])
    
    # Duplications
    for i in range(len(name)):
        typos.append(name[:i] + name[i] + name[i:])
    
    # Transpositions
    for i in range(len(name)-1):
        typos.append(name[:i] + name[i+1] + name[i] + name[i+2:])
    
    # Alt encodings (ASCII )
    alternatives = {'s': '5', 'l': '1', 'o': '0', 'a': '4', 'e': '3', 'i': '1', 't': '7'}
    for i, c in enumerate(name):
        if c.lower() in alternatives:
            typos.append(name[:i] + alternatives[c.lower()] + name[i+1:])
    
    return [f"{typo}.{tld}" for typo in set(typos)]

async def check_domains(domains):
    resolver = aiodns.DNSResolver()
    tasks = [check_domain(domain, resolver) for domain in domains]
    return await asyncio.gather(*tasks)

async def get_original_domain_content(domain):
    url = f"https://{domain}"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    return await response.text()
        except:
            return ""
    return ""

def extract_keywords(content):
    words = content.lower().split()
    return list(set([word for word in words if len(word) > 3]))

async def analyze_domain(domain, original_domain):
    url = f"https://{domain}"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # DOM Content Analysis
                    original_domain_content = await get_original_domain_content(original_domain)
                    original_keywords = extract_keywords(original_domain_content)
                    keyword_count = sum(1 for keyword in original_keywords if keyword in content.lower())
                    
                    # SSL Certificate Analysis
                    ssl_info = ssl.create_default_context().wrap_socket(socket.create_connection((domain, 443)), server_hostname=domain)
                    cert = ssl_info.getpeercert()
                    cert_expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (cert_expiry - datetime.now()).days
                    
                    # WHOIS Data Analysis
                    domain_info = whois.whois(domain)
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    days_since_creation = (datetime.now() - creation_date).days
                    
                    # URL Structure Analysis
                    extracted = tldextract.extract(domain)
                    suspicious_words = ['official', 'login', 'account', 'secure', 'verify', 'update']
                    contains_suspicious_word = any(word in extracted.domain for word in suspicious_words)
                    
                    # Redirect Analysis
                    final_url = str(response.url)
                    is_redirect = final_url != url
                    
                    suspicion_score = 0
                    reasons = []
                    
                    if keyword_count > len(original_keywords) // 2:
                        suspicion_score += 1
                        reasons.append("High number of original domain keywords")
                    
                    if days_until_expiry < 30:
                        suspicion_score += 1
                        reasons.append("SSL certificate expiring soon")
                    
                    if days_since_creation < 60:
                        suspicion_score += 2
                        reasons.append("Domain recently created")
                    
                    if contains_suspicious_word:
                        suspicion_score += 1
                        reasons.append("Contains suspicious word in domain")
                    
                    if is_redirect:
                        suspicion_score += 1
                        reasons.append(f"Redirects to {final_url}")
                    

                    return {
                        'domain': domain,
                        'suspicion_score': suspicion_score,
                        'reasons': reasons,
                        'is_suspicious': suspicion_score > 2
                    }
                else:
                    return {
                        'domain': domain,
                        'error': f"HTTP status code: {response.status}",
                        'is_suspicious': False
                    }
        except aiohttp.ClientError as e:
            return {
                'domain': domain,
                'error': f"Connection error: {str(e)}",
                'is_suspicious': False
            }
        except Exception as e:
            return {
                'domain': domain,
                'error': f"Unexpected error: {str(e)}",
                'is_suspicious': False
            }

def read_domain_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

async def main(domains):
    start_time = time.time()
    domain_summaries = []

    for original_domain in domains:
        print(f"\n{INFO} Checking typosquats for: {BLUE}{original_domain}{ENDC}")
        typosquatted_domains = generate_typos(original_domain)
        
        results = await check_domains(typosquatted_domains)
        
        for result in results:
            if "registered and resolves" in result:
                print(f"{WARNING} {result.replace('resolves to', f'resolves to {RED}')}{ENDC}")
            elif "registered but does not resolve" in result:
                print(f"{WARNING} {result}")
            elif "not registered" in result:
                print(f"{SUCCESS} {result}")
            else:
                print(f"{ERROR} {result}")
        
        # generate summary for each domain
        total_domains = len(results)
        status_counter = Counter([r.split(' is ')[1].split(' and ')[0] for r in results if ' is ' in r])
        
        print(f"\n{INFO} Summary for {BLUE}{original_domain}{ENDC}:")
        print(f"Total domains checked: {total_domains}")
        print(f"Registered domains: {YELLOW}{status_counter['registered']}{ENDC}")
        print(f"Unregistered domains: {GREEN}{status_counter['not registered']}{ENDC}")
        print(f"Domains resolving to IP: {RED}{sum(1 for r in results if 'resolves to' in r)}{ENDC}")
        print(f"Registered domains not resolving: {YELLOW}{status_counter['registered but does not resolve to an IP']}{ENDC}")
        print(f"Errors encountered: {RED}{sum(1 for r in results if r.startswith('Error'))}{ENDC}")
        print("-" * 50)

        # Analyse suspicious domains
        analyze_results = await asyncio.gather(*[analyze_domain(domain, original_domain) for domain in typosquatted_domains], return_exceptions=True)
        
        valid_results = [r for r in analyze_results if not isinstance(r, Exception) and r is not None]
        suspicious_domains = [r for r in valid_results if r.get('is_suspicious', False)]
        
        print(f"\n{INFO} Suspicious domains for {BLUE}{original_domain}{ENDC}:")
        for domain in suspicious_domains:
            print(f"{WARNING} Domain: {RED}{domain['domain']}{ENDC}")
            print(f"Suspicion Score: {YELLOW}{domain.get('suspicion_score', 'N/A')}{ENDC}")
            print(f"Reasons: {', '.join(domain.get('reasons', []))}")
            print("---")

        errors = len(analyze_results) - len(valid_results)
        print(f"{ERROR} Errors encountered: {RED}{errors}{ENDC}")

        # Create domain summaries
        domain_summary = {
            'domain': original_domain,
            'total_checked': total_domains,
            'registered': status_counter['registered'],
            'unregistered': status_counter['not registered'],
            'resolving': sum(1 for r in results if 'resolves to' in r),
            'suspicious': len(suspicious_domains),
            'errors': errors
        }
        domain_summaries.append(domain_summary)

    # print overall summary
    print(f"\n{INFO} Overall Summary of Typosquatted domains:")
    for summary in domain_summaries:
        print(f"{BOLD}{summary['domain']}{ENDC}: "
              f"{YELLOW}{summary['registered']}{ENDC} registered, "
              f"{GREEN}{summary['unregistered']}{ENDC} unregistered, "
              f"{RED}{summary['resolving']}{ENDC} resolving DNS names, "
              f"{RED}{summary['suspicious']}{ENDC} suspicious, "
              f"{RED}{summary['errors']}{ENDC} errors")

    end_time = time.time()
    print(f"\n{INFO} Total execution time: {YELLOW}{end_time - start_time:.2f}{ENDC} seconds")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for typosquatted domains")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domains", nargs="+", help="Domain(s) to check for typosquats")
    group.add_argument("-f", "--file", help="Path to a file containing a list of domains, one per line")
    args = parser.parse_args()

    if args.file:
        domains = read_domain_file(args.file)
    else:
        domains = args.domains

    banner()
    asyncio.run(main(domains))
