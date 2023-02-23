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

from modules.http_authent import http_auth
from modules.default_error_page import first_check
from modules.default_tests import all_default_tests
from modules.bf_top_pass import bf_top_password
from modules.predefined_request import predefined_request_send

from config.color_config import INFO, found, not_found, action_not_found, action_found


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

UserAgent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}


def check_param(inputs, url):
    global username_input
    username_input = inputs.split(":")[0]
    global password_input
    password_input = inputs.split(":")[1]

    req = requests.get(url, verify=False, timeout=10, headers=UserAgent, cookies=cookie_)

    if username_input in req.text and password_input in req.text:
        if len(inputs.split(":")) > 2:
            global other_param
            other_param = inputs.split(":")[2]
            global other_param_value
            other_param_value = input(" {} Please define the {} parameter [login:pass]: ".format(INFO, inputs.split(":")[2]))
    else:
        other_input_value = input(" {} CMS basic input dosn't seem ok, please define manual input [login:pass]: ".format(INFO))
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
                    tdp = adt.test_default_password(url, username_input, password_input, username, password, fc, nomessage, cookie_)
                if not tdp and bf:
                    print(" {} Default credentials don't seem to work".format(action_not_found))
                    for d in default_passwords[dp]:
                        username = d.split(":")[0]
                        btp = bf_top_password(url, wordlist, username_input, password_input, fc, nomessage, cookie_, user_known, onlypass, username)
    if not tdp:
        print("-"*30)
        print(" {} Test user-as-pass".format(INFO))
        user_as_pass = adt.default_user_as_pass(url, username_input, password_input, fc, nomessage, cookie_)
        if not user_as_pass:
            print(" {} user-as-pass account not found".format(action_not_found))
        if bf:
            btp = bf_top_password(url, wordlist, username_input, password_input, fc, nomessage, cookie_, user_known, onlypass)
            if not btp:
                print(" {} Default Account not found".format(action_not_found))


def main(url, cookie_, domain=False, cms_value=True):
    fg = finger_print()

    adt = all_default_tests();

    app_type = fg.whatisapp(url) #Check what is the website type

    if app_type != "web":
        # Launch basic http authent
        if domain:
            adt.default_domain_test(url, domain, app_type, cookie_, nomessage)
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
                    req_inputs = requests.get(url, verify=False, timeout=10, headers=UserAgent, cookies=cookie_)
                    if credz_input[0] in req_inputs.text and credz_input[1] in req_inputs.text:
                        print("      {}Inputs \"{}\" found in page".format(INFO, credz_input))
                        test_credz(url, credz_input, adt, cms_name)
                        if domain:
                            adt.default_domain_test(url, domain, app_type, cookie_, nomessage, inputs=credz_input)
                else:
                    print(" {} CMS template not found".format(action_not_found))
                    main(url, domain=domain, cms_value=False)
            else:
                other_name = fg.other_check(url, onlypass)
                # Check if the techno is know and in the db
                if len(other_name) > 2:
                    if onlypass:
                        fc = first_check(url, None, other_name)
                        bf_top_password(url, wordlist, None, other_name, fc, nomessage, cookie_, user_known, onlypass)
                    else:   
                        #if there are more 2 parameter to send
                        credz_input = other_input(other_name)
                        test_credz(url, credz_input, adt, other_name)
                        if domain:
                            adt.default_domain_test(url, domain, app_type, cookie_, nomessage, inputs=credz_input)
                elif len(other_name) == 2:
                    credz_input = "{}:{}".format(other_name[0], other_name[1])
                    test_credz(url, credz_input, adt)
                    if domain:
                        adt.default_domain_test(url, domain, app_type, cookie_, nomessage, inputs=credz_input)
                else:
                    print(" {} Nothing template found".format(action_not_found))
        except KeyboardInterrupt:
            print(" {}Canceled by keyboard interrupt (Ctrl-C) ".format(INFO))
            sys.exit()
            """if not file_url:
                print(" {}Canceled by keyboard interrupt (Ctrl-C) ".format(INFO))
                sys.exit()
            else:
                print(" {}Canceled by keyboard interrupt (Ctrl-C), next site ".format(INFO))"""
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
    parser.add_argument('--cookie', help="To add cookie", required=False, dest='cookie_')
    parser.add_argument('--onlypass', '--onlypass', help="If there is just only password to test", required=False, dest='onlypass', action="store_true")
    parser.add_argument('--request', help="Json file containing the indications to carry out for a request", dest='req_file')
    parser.add_argument('--nomessage', help="if the value of this option is not found in the source code of the page it will be considered as potentially found", dest='nomessage')



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
    cookie_ = results.cookie_
    req_file = results.req_file
    nomessage = results.nomessage

    if cookie_:
        cookie_ = {cookie_.split(":")[0]: cookie_.split(":")[1]}

    if req_file:
        predefined_request_send(req_file, bf, wordlist)
        sys.exit()


    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> or -h for help".format(INFO))
        parser.print_help()
        sys.exit()
    if inputs:
        with open("fingerprint/inputs.txt", "a+") as add_input:
            add_input.write(inputs+"\n")
    if key_words:
        for k in key_words:
            with open(wordlist, "a+") as add_pass:
                add_pass.write(k+"\n")
    if not urls_file:
        print("\033[35m URL: {}\033[0m".format(url))
        #url = url + "/" if url.split("/")[-1] != "" else url
        main(url, cookie_, domain if domain else False)
    else:
        with open(urls_file, "r+") as uf:
            for u in uf.readlines():
                print(" [i] URL: {}".format(u))
                main(u.strip(), cookie_, domain if domain else False)