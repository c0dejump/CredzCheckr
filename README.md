# CredzCheckr
Testing default web credentials

# Usage

```
usage: credzcheckr.py [-h] [-u URL] [-U URLS_FILE] [-uap UAP] [-w WORDLIST] [-b] [-i INPUTS]

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
	  -uap, --user-as-pass  test user-as-pass
	  --user USER_KNOWN     If you want test just a known username
	  --onlypass ONLYPASS, --onlypass ONLYPASS
	                        If there is just only password to test

```

# Exemples

```
	//Basic
	python3 credzcheckr.py -u URL/login.php 

	// With particular inputs
	python3 credzcheckr.py -u URL/login.php -i user_input:password_input

	// With a domain name
	python3 credzcheckr.py -u facebook.com/login.php -d facebook

	// BF default username/password
	python3 credzcheckr.py -u URL/login.php -b
```

![alt tag](https://github.com/c0dejump/CredzCheckr/blob/master/static/bf_credz.png)


# TODO

- [ ] Get nmap file to scan
- [ ] Captcha bypass
- [ ] Personal header/cookie/values...
- [ ] Different credentials forms
- [ ] Without input directly in requests

# Credits

- ztgrace for "changeme" tool https://github.com/ztgrace/changeme


