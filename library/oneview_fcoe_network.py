#!/usr/bin/python
# -*- coding: utf-8 -*-
###
# Copyright (2016-2017) Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

ANSIBLE_METADATA = {'status': ['stableinterface'],
                    'supported_by': 'committer',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: oneview_fcoe_network
short_description: Manage OneView FCoE Network resources.
description:
    - Provides an interface to manage FCoE Network resources. Can create, update, or delete.
version_added: "2.3"
requirements:
    - "python >= 2.7.9"
    - "hpOneView >= 3.1.0"
author: "Gustavo Hennig (@GustavoHennig)"
options:
    state:
        description:
            - Indicates the desired state for the FCoE Network resource.
              C(present) will ensure data properties are compliant with OneView.
              C(absent) will remove the resource from OneView, if it exists.
        choices: ['present', 'absent']
    data:
        description:
            - List with FCoE Network properties.
        required: true

extends_documentation_fragment:
    - oneview
    - oneview.validateetag
'''

EXAMPLES = '''
- name: Ensure that FCoE Network is present using the default configuration
  oneview_fcoe_network:
    config: "{{ config_file_path }}"
    state: present
    data:
      name: 'Test FCoE Network'
      vlanId: '201'

- name: Ensure that FCoE Network is absent
  oneview_fcoe_network:
    config: "{{ config_file_path }}"
    state: absent
    data:
      name: 'New FCoE Network'
'''

RETURN = '''
fcoe_network:
    description: Has the facts about the OneView FCoE Networks.
    returned: On state 'present'. Can be null.
    type: complex
'''

from ansible.module_utils.basic import *
from _ansible.module_utils.oneview import OneViewModuleBase, ResourceComparator

FCOE_NETWORK_CREATED = 'FCoE Network created successfully.'
FCOE_NETWORK_UPDATED = 'FCoE Network updated successfully.'
FCOE_NETWORK_DELETED = 'FCoE Network deleted successfully.'
FCOE_NETWORK_ALREADY_EXIST = 'FCoE Network already exists.'
FCOE_NETWORK_ALREADY_ABSENT = 'Nothing to do.'


class FcoeNetworkModule(OneViewModuleBase):
    def __init__(self):

        add_arg_spec = dict(data=dict(required=True, type='dict'),
                            state=dict(
                                required=True,
                                choices=['present', 'absent']))

        super(FcoeNetworkModule, self).__init__(additional_arg_spec=add_arg_spec,
                                                validate_etag_support=True)

    def execute_module(self):
        resource = self.__get_by_name()

        if self.state == 'present':
            return self.__present(resource)
        elif self.state == 'absent':
            return self.__absent(resource)

    def __present(self, resource):
        changed = False
        if "newName" in self.data:
            self.data["name"] = self.data.pop("newName")

        if not resource:
            resource = self.oneview_client.fcoe_networks.create(self.data)
            msg = FCOE_NETWORK_CREATED
            changed = True
        else:
            merged_data = resource.copy()
            merged_data.update(self.data)

            if ResourceComparator.compare(resource, merged_data):
                msg = FCOE_NETWORK_ALREADY_EXIST
            else:
                resource = self.oneview_client.fcoe_networks.update(merged_data)
                changed = True
                msg = FCOE_NETWORK_UPDATED

        return dict(
            msg=msg,
            changed=changed,
            ansible_facts=dict(fcoe_network=resource)
        )

    def __absent(self, resource):

        if resource:
            self.oneview_client.fcoe_networks.delete(resource)
            return {"changed": True, "msg": FCOE_NETWORK_DELETED}
        else:
            return {"changed": False, "msg": FCOE_NETWORK_ALREADY_ABSENT}

    def __get_by_name(self):
        result = self.oneview_client.fcoe_networks.get_by('name', self.data['name'])
        return result[0] if result else None


def main():
    FcoeNetworkModule().run()


if __name__ == '__main__':
    main()
