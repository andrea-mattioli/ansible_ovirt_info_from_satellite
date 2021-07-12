#!/usr/bin/python

# Copyright: (c) 2021, Andrea Mattioli <amattiol@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: ovirt_info_from_satellite
short_description: This module get templete info using satellite auth
version_added: "1.0.0"
description: This module get templete info using satellite auth, so you don't need RHV auth but only a compute resource configured on satellite
options:
    sat_host:
        description: This is the satellite host ex. satellite.local.domain.
        required: true
        type: str
    sat_username:
        description: This is the satellite user.
        required: true
        type: str
    sat_pass:
        description: This is the satellite password.
        required: true
        type: str
    compute_resource:
        description: This is the satellite compute_resource
        required: true
        type: str
    template_id:
        description: This is the RHV template_id.
        required: true
        type: str
author:
    - Andrea Mattioli (@andrea-mattioli)
'''

EXAMPLES = r'''
- name: Get template info
  ovirt_info_from_satellite:
    sat_host: satellite.local.domain
    sat_username: admin
    sat_pass: password
    compute_resource: name_of_my_compute_resource
    templete_id: my_template_id
  register: my_var
'''

import requests
import re
import http.cookiejar
from lxml import etree
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from ansible.module_utils.basic import AnsibleModule

class Login_Satellite(object):
    def __init__(self,sat_host,compute_resource):
        self.headers={
            "User-Agent":"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:61.0) Gecko/20100101 Firefox/61.0",
            "Host":sat_host,
            "Referer":"https://%s/users/login"%(sat_host)
        }
        self.login_url="https://%s/users/login"%(sat_host)
        self.post_url="https://%s/users/login"%(sat_host)
        self.logined_url = "https://%s/compute_resources/%s/template_selected"%(sat_host,compute_resource)
        self.session=requests.Session()
        self.session.cookies=http.cookiejar.MozillaCookieJar("/tmp/sat.txt")

    def get_authenticity_token(self):
        response=self.session.get(self.login_url,headers=self.headers,verify=False).text
        my_resp=etree.HTML(response)
        authenticity_token = my_resp.xpath('//script[@type="text/javascript"]/text()')[0].split("AUTH_TOKEN =",1)[1].strip()[1:][:-2]
        return authenticity_token

    def get_csrf_token(self):
        response=self.session.get(self.login_url,headers=self.headers,verify=False).text
        my_resp=etree.HTML(response)
        csrf_token = my_resp.xpath('//meta[@name="csrf-token"]/@content')[0]
        return csrf_token

    def login(self,login,password):
        post_data={
            "authenticity_token":self.get_authenticity_token(),
            "login[login]":login,
            "login[password]":password
        }
        self.session.post(self.post_url,data=post_data,headers=self.headers,verify=False)
        self.session.cookies.save(ignore_discard=True, ignore_expires=True)

    def disk_id(self,template_id):
        post_data={
           "template_id":template_id
        }
        headers={
           "X-CSRF-Token":self.get_csrf_token(),
           "X-Requested-With": "XMLHttpRequest"
        }
        self.session.cookies.load("/tmp/sat.txt",ignore_discard=True, ignore_expires=True)
        response = self.session.post(self.logined_url,data=post_data,headers=headers,verify=False).text
        return response

def main():
    module_args = dict(
        sat_host=dict(type='str', required=True),
        sat_username=dict(type='str', required=True),
        sat_pass=dict(type='str', required=True),
        compute_resource=dict(type='str', required=True),
        templete_id=dict(type='str', required=True),

    )
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    sat=Login_Satellite(module.params['sat_host'],module.params['compute_resource'])
    sat.get_authenticity_token()
    sat.login(module.params['sat_username'],module.params['sat_pass'])
    result = sat.disk_id(module.params['templete_id'])

    module.exit_json(**result)

    if module.check_mode:
        module.exit_json(**result)

if __name__ == '__main__':
   main()
