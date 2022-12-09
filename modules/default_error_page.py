#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys

UserAgent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}

def first_check(url, username_input, password_input, other_param_value=False):
    """ 
    first_check: gets the page size for comparison when testing default passwords
    """
    if username_input == None:
        login ={password_input: "azefraezfr"}
        req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
        page_len = len(req.text)
        if req.status_code == 200:
            return page_len
        elif req.status_code in [301, 302]:
            req_follow = requests.post(url, data=login, verify=False, allow_redirects=True, timeout=10, headers=UserAgent)
            req_follow_url = requests.get(req_follow.url, verify=False, timeout=10)
            return len(req_follow_url.text)
        elif req.status_code == 403:
            print("\033[31m! {} Verify if no need csrf token or other same...\033[0m".format(req.status_code))
            sys.exit()
        else:
            print(req.status_code)
            sys.exit()
    else:
        login ={username_input: "azefraezfr", password_input: "azefraezfr"}
        req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
        page_len = len(req.text)
        if req.status_code == 200:
            print("200 ok")
            return page_len
        elif req.status_code in [301, 302]:
            print("30x redirect")
            req_follow = requests.post(url, data=login, verify=False, allow_redirects=True, timeout=10, headers=UserAgent)
            req_follow_url = requests.get(req_follow.url, verify=False, timeout=10, headers=UserAgent)
            return len(req.text), len(req_follow_url.text)
        elif req.status_code == 403:
            print("\033[31m! {} Verify if no need csrf token or other same...\033[0m".format(req.status_code))
            sys.exit()
        else:
            print(req.status_code)
            sys.exit()