# CredzCheckr
Testing default web credentials

# Usage

```
usage: credzcheckr.py [-h] [-u URL] [-U URLS_FILE] [-uap UAP] [-w WORDLIST] [-b] [-i INPUTS]

 optional arguments:
	-h, --help            show this help message and exit                                                   
	-u URL                URL login to test [required] 
	-U, --urls_file       Provide file instead of url, one per line.                                        
	--user USER_KNOWN     If you want test just a known username                                            
	-uap, --user-as-pass  test user-as-pass                                                                 
	-w                    list of your passwords to test Default: credz/wordlists/top_200_default_passwd.txt            
	-b,   --bruteforce      Bruteforce username/password                                                      
	-i INPUTS, --inputs INPUTS
	  if that not found inputs during the scan, this option add auto in inputs.txt file. 
	  Ex: -i "user:passwd"                                                        
	-k [KEY_WORDS [KEY_WORDS ...]], --key_words [KEY_WORDS [KEY_WORDS ...]] 
	if you want add personal password in list                     
	-d DOMAIN, --domain DOMAIN 
	Add domain to test all combinaison like domain@2019, domain2021...
```

# Exemples

```
	//Basic
	python3 credzcheckr.py -u URL/login.php 

	// With particular inputs
	python3 credzcheckr.py -u URL/login.php -i user_input:password_input

	// With a domain name
	python3 credzcheckr.py -u facebook.com/login.php -d facebook
```

# TODO

- [ ] Get nmap file to scan

# Credits

- ztgrace for "changeme" tool https://github.com/ztgrace/changeme


