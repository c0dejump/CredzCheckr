import requests
import json
import sys

from modules.default_tests import all_default_tests
from modules.bf_top_pass import bf_top_password

from config.color_config import INFO, found, not_found, action_not_found, action_found

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def first_check(url, username_input, password_input, datas, header, data):
    """ 
    first_check: gets the page size for comparison when testing default passwords
    """
    datas[username_input] = "azefraezfr"
    datas[password_input] = "azefraezfr"


    if data["infos"]["type"] == "json":
        datas = dict(sorted(datas.items(), key=lambda x: x[0]))
        datas = json.dumps(datas)

    print("url: {}".format(url))
    print("datas: {}".format(datas))
    print("headers: {}\n".format(header))
    
    req = requests.post(url, data=datas, headers=header, verify=False, allow_redirects=False, timeout=10)

    #print(req.text)
    page_len = len(req.text)
    if req.status_code == 200:
        print("200 ok")
        return page_len
    elif req.status_code in [301, 302]:
        print("30x redirect")
        req_follow = requests.post(url, data=datas, verify=False, allow_redirects=True, timeout=10, headers=header)
        req_follow_url = requests.get(req_follow.url, verify=False, timeout=10, headers=header)
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


def predefined_request_send(req_file, bf, wordlist):

    adt = all_default_tests()

    with open(req_file, 'r') as f:
        data = json.load(f)

        url = data["infos"]["url"]

        u = data["credz_inputs"]["_username_input"]
        p = data["credz_inputs"]["_password_input"]

        header = data["header"]

        datas = {}

        for d in data["other_values"]:
            datas[d] = data["other_values"][d]

        fc = first_check(url, u, p, datas, header, data)
        #print(fc)

        if data["infos"]["method"] == "POST" and data["infos"]["type"] != "json":
            print(" {} Test user-as-pass".format(INFO))
            user_as_pass = adt.default_user_as_pass(url, u, p, fc)
            if not user_as_pass:
                print(" {} user-as-pass account not found".format(action_not_found))
            if bf:
                btp = bf_top_password(url, wordlist, u, p, fc)
                if not btp:
                    print(" {} Default Account not found".format(action_not_found))
        elif data["infos"]["method"] == "POST" and data["other_values"] == {} and data["infos"]["type"] == "json":
            print("In progress")
        elif data["infos"]["method"] == "POST" and data["other_values"] != {} and data["infos"]["type"] == "json":
            print("In progress")
        else:
            print("If you have another case/form of connection do not hesitate to inform me on 'https://github.com/c0dejump/CredzCheckr/issues'")
