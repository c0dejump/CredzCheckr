#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This is a part of CMSeeK, check the LICENSE file for more information
# Copyright (c) 2018 - 2020 Tuhinshubhra

# YAF version detection
# Rev 1

import cmseekdb.basic as cmseek
import re

def start(source):
    regex = re.findall(r'Powered by YAF.NET (\d.*?)</a>', source)
    if regex != []:
        if regex[0] != '' and regex[0] != ' ':
            version = regex[0].replace(' ', '')
            cmseek.success('YAF version ' + cmseek.bold + cmseek.fgreen + version + cmseek.cln + ' detected')
            return version

    cmseek.error('Version detection failed!')
    return '0'
