#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import sys, os, re
from bs4 import BeautifulSoup


def cms_input(cms):
	cms = cms.lower()
	#input username & password
	cms_value = {
	"wordpress": "log:pwd",
	"drupal": "name:pass",
	"ez publish": "Login:Password",
	"expressionengine":  "username:password",
	"joomla": "username:password",
	"shopify":"",
	"webflow cms": "",
	"umbraco": "Username:Password"
	}
	if cms_value[cms] != "":
		return cms_value[cms]
	else:
		return False