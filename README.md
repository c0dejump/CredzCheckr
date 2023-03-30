# CredzCheckr
Testing default web credentials

### v.1.5

# News v1.X

- "rd" option
- News default usernames, passwords, inputs endpoints
- fix any bugs


# Usage

```
usage: credzcheckr.py [-h] [-u URL] [-U] [-w] [-b] [-i INPUTS] [-k [KEY_WORDS ...]] [-d DOMAIN]
                      [-X POST_REQUEST] [-uap] [--user USER_KNOWN] [--cookie COOKIE_] [--onlypass]
                      [--request REQ_FILE] [--nomessage NOMESSAGE]

 optional arguments:
  -h, --help            show this help message and exit
  -u URL                URL login to test [required]
  -U, --urls_file       Provide file instead of url, one per line.
  -w                    list of your passwords to test Default:
                        credz/wordlists/top_200_default_passwd.txt
  -b, --bruteforce      Bruteforce username/password
  -i INPUTS, --inputs INPUTS
                        if that not found inputs during the scan, this option add auto in inputs.txt
                        file. Ex: -i "user:passwd" 
  -k [KEY_WORDS ...], --key_words [KEY_WORDS ...]
                        if you want add personal password in list
  -d DOMAIN, --domain DOMAIN
                        Add domain to test all combinaison like domain@2019, domain2021...
  -X POST_REQUEST       POST requests URL Ex: credzcheckr -u toto.com/login -X
                        toto.com/login_check
  -uap, --user-as-pass  test user-as-pass
  --user USER_KNOWN     If you want test just a known username
  --cookie COOKIE_      To add cookie
  --onlypass, --onlypass
                        If there is just only password to test
  --rf REQ_FILE         Json file containing the indications to carry out for a request
  --rd REQ_DATA         TXT file containing the data of the requests with 'BFU' & 'BFP' params (exemple in config/requests_data.txt)
  --nomessage NOMESSAGE
                        if the value of this option is not found in the source code of the page it
                        will be considered as potentially found


```

# Exemples

```
	//Basic
	python3 credzcheckr.py -u URL/login.php 

	// With particular inputs
	python3 credzcheckr.py -u URL/login.php -i "user_input:password_input"

	// With a domain name
	python3 credzcheckr.py -u facebook.com/login.php -d facebook

	// BF default username/password
	python3 credzcheckr.py -u URL/login.php -b

	// With specific format requests file
	python3 credzcheckr.py --rf config/request_exemple.json

	// With nomessage option
	python3 credzcheckr.py -u URL/login.php -b --nomessage "incorrect"

	// With POST redirect URL
	python3 credzcheckr.py -u URL/login.php -X URL/login_check.php 
```

![alt tag](https://github.com/c0dejump/CredzCheckr/blob/main/static/bf_credz.png)


# TODO

- [IP] Different credentials forms
- [ ] Get nmap file to scan
- [ ] Captcha bypass
- [ ] Selenium when javascript do enable
- [ ] Bruteforce with user@domain.(fr/en...)

# Credits

- ztgrace for "changeme" tool https://github.com/ztgrace/changeme
- For other default password wordlist: 
  - https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.txt

