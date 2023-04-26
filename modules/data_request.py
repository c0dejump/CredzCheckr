import requests
import json
import sys

from modules.default_tests import all_default_tests
from modules.bf_top_pass import bf_top_password

from config.color_config import INFO, found, not_found, action_not_found, action_found

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def first_check(url, req_data):
    """ 
    first_check: gets the page size for comparison when testing default passwords
    """
    datas = ""
    with open(req_data, "r") as read_file:
        for rf in read_file:
            datas = rf.replace("BFU", "azefraezfr").replace("BFP", "azefraezfr")
    
    req = requests.post(url, data=datas, verify=False, allow_redirects=False, timeout=10)

    #print(req.text)
    page_len = len(req.text)
    if req.status_code == 200:
        print("200 ok")
        return page_len
    elif req.status_code in [301, 302]:
        print("30x redirect")
        req_follow = requests.post(url, data=datas, verify=False, allow_redirects=True, timeout=10)
        req_follow_url = requests.get(req_follow.url, verify=False, timeout=10)
        return page_len, len(req_follow_url.text)
    elif req.status_code in [403, 401]:
        print(req.status_code)
        return page_len
    elif req.status_code in [400]:  
        contin = input("Return 400 response code continue ? [y:n]")
        if contin == "y" or contin == "Y":
            return page_len
    else:
        print(req.status_code)
        sys.exit()


def data_requests(url, req_data, bf, wordlist):
    usernames = []
    datas = ""

    s = requests.session()
    s.verify=False

    fc = first_check(url, req_data)

    with open("credz/wordlists/top_default_username.txt", "r") as users:
        usernames += users

    for user in usernames:
        user = user.replace("\n","")
        with open(wordlist, "r+") as top_pass:
            for tp in top_pass.read().splitlines():
                with open(req_data, "r") as read_file:
                    for rf in read_file:
                        datas = rf.replace("BFU", user).replace("BFP", tp)
                req = s.post(url, data=datas, timeout=10)
                if len(req.text) != fc and req.status_code not in [401, 403]:
                    print("  {}Potentially account found: {}:{} [{}b]".format(found, user, tp, len(req.content)))
                sys.stdout.write("\033[34m{}: {}\033[0m\r".format(user, tp))
                sys.stdout.write("\033[K")