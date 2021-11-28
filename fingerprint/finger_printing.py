#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback
import os
import json
from bs4 import BeautifulSoup
import mmh3
import codecs
import time

from .favicon_fingerprint import favinger
from color_config import INFO, found, not_found, action_not_found, action_found

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

UserAgent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}

class finger_print:

    def whatisapp(self, url):
        req = requests.get(url, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
        if req.status_code in [403, 401] and "WWW-Authenticate" in req.headers:
            print(" {} Basic authentification".format(INFO))
            return "basic_auth"
        else:
            return "web"


    def cms_check(self, url, second_test=False):
        if second_test:
            url_base = url.split("/")[2] if len(url.split("/")) < 5 else "{}".format("_".join(url.split("/")[2:-1]))
        else:
            url_base = "".join(url.split("/")[1:3])
        if not os.path.exists("fingerprint/CMSeeK/Result/{}/cms.json".format(url)):
            try:
                os.system('python3 fingerprint/CMSeeK/cmseek.py -u {} -o --follow-redirect >/dev/null'.format(url_base))
                with open("fingerprint/CMSeeK/Result/{}/cms.json".format(url_base)) as result:
                    data = json.load(result)
                if data["cms_name"] != "":
                    return data["cms_name"]
                else:
                    if not second_test:
                        self.cms_check(url, second_test=True)
                    else:
                        return False
            except Exception:
                #traceback.print_exc() #DEBUG
                pass


    def other_check(self, url):
        print(" {} Search technologie".format(INFO))

        techno_found = False
        hash_fav = 0

        domain = "/".join(url.split("/")[:3])
        url_fav =  "{}favicon.ico".format(domain) if domain[-1] == "/" else "{}/favicon.ico".format(domain)
        req_fav = requests.get(url_fav, verify=False, timeout=10, allow_redirects=True)
        req = requests.get(url, verify=False, timeout=10, allow_redirects=True, headers=UserAgent)
        if req_fav.status_code == 200:
            fav_found = False
            favicon = codecs.encode(req_fav.content,"base64")
            hash_fav = mmh3.hash(favicon)
            print("   {} Favicon.ico hash: {}".format(action_found, hash_fav))
            for fg in favinger:
                if hash_fav == fg:
                    techno_found = True
                    print("   {} {} found".format(action_found, favinger[fg]))
                    return favinger[fg]
        else:
            if "dana-na" in req.url:
                print(" {} Pulse secure found".format(action_found, hash_fav))
                return "pulse-secure"
        if not techno_found:
            print("   {} favicon not found in template database".format(action_not_found))
            username_input = False
            password_input = False
            print(" {} Search input".format(INFO))
            #TODO search input with a percentage
            soup = BeautifulSoup(req.text, "html.parser")
            #print(soup) #debug
            for p in soup.find_all('input'):
                with open("fingerprint/inputs.txt", "r") as default_input:
                    for di in default_input.read().splitlines():
                        try:
                            pid = p["id"]
                            type_ = p["type"]
                        except:
                            type_ = p["type"]
                            pid = False
                        try:
                            if di.split(":")[0] == p["name"] and username_input != di.split(":")[0]:
                                if pid and di.split(":")[0] == p["id"] and type_ != "submit":
                                    print(" {} input username found: {}".format(action_found, p["name"]))
                                    username_input = p["name"]
                                elif pid and di.split(":")[0] != p["id"] and type_ != "submit":
                                    print(" {} input username found: {}".format(action_found, p["name"]))
                                    username_input = p["name"]
                                else:
                                    if type_ != "submit":
                                        print(" {} input username found: {}".format(action_found, p["name"]))
                                        username_input = p["name"]
                        except:
                            pass
                        try:
                            if di.split(":")[1] == p["name"] and password_input != di.split(":")[1]:
                                if pid and di.split(":")[1] == p["id"]:
                                    print(" {} input password found: {}".format(action_found, p["name"]))
                                    password_input = p["name"]
                                elif pid and di.split(":")[1] != p["id"]:
                                    print(" {} input password found: {}".format(action_found, p["name"]))
                                    password_input = p["name"]
                                else:
                                    print(" {} input password found: {}".format(action_found, p["name"]))
                                    password_input = p["name"]
                        except:
                            pass
                            #traceback.print_exc() 
            if username_input and password_input:
                return username_input, password_input
            else:
                print(" {} Inputs not found".format(action_not_found))
                return "n"

