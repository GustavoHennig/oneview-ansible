#!/usr/bin/python
# -*- coding: utf-8 -*-
###
# Copyright (2016) Hewlett Packard Enterprise Development LP
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
module: oneview_fc_network
short_description: Manage OneView Fibre Channel Network resources.
description:
    - Provides an interface to manage Fibre Channel Network resources. Can create, update, and delete.
version_added: "2.3"
requirements:
    - "python >= 2.7.9"
    - "hpOneView >= 3.1.0"
author: "Bruno Souza (@bsouza)"
options:
    state:
        description:
            - Indicates the desired state for the Fibre Channel Network resource.
              C(present) will ensure data properties are compliant with OneView.
              C(absent) will remove the resource from OneView, if it exists.
        choices: ['present', 'absent']
    data:
        description:
            - List with the Fibre Channel Network properties.
        required: true

extends_documentation_fragment:
    - oneview
    - oneview.validateetag
'''

EXAMPLES = '''
- name: Ensure that a Fibre Channel Network is present using the default configuration
  oneview_fc_network:
    config: "{{ config_file_path }}"
    state: present
    data:
      name: 'New FC Network'

- name: Ensure that the Fibre Channel Network is present with fabricType 'DirectAttach'
  oneview_fc_network:
    config: "{{ config_file_path }}"
    state: present
    data:
      name: 'New FC Network'
      fabricType: 'DirectAttach'

- name: Ensure that Fibre Channel Network is absent
  oneview_fc_network:
    config: "{{ config_file_path }}"
    state: absent
    data:
      name: 'New FC Network'
'''

RETURN = '''
fc_network:
    description: Has the facts about the OneView FC Networks.
    returned: On state 'present'. Can be null.
    type: complex
'''

from ansible.module_utils.basic import *
from _ansible.module_utils.oneview import OneViewModuleBase, ResourceComparator

FC_NETWORK_CREATED = 'FC Network created successfully.'
FC_NETWORK_UPDATED = 'FC Network updated successfully.'
FC_NETWORK_DELETED = 'FC Network deleted successfully.'
FC_NETWORK_ALREADY_EXIST = 'FC Network already exists.'
FC_NETWORK_ALREADY_ABSENT = 'Nothing to do.'


class FcNetworkModule(OneViewModuleBase):
    def __init__(self):

        add_arg_spec = dict(data=dict(required=True, type='dict'),
                            state=dict(
                                required=True,
                                choices=['present', 'absent']))

        super(FcNetworkModule, self).__init__(additional_arg_spec=add_arg_spec,
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
            resource = self.oneview_client.fc_networks.create(self.data)
            msg = FC_NETWORK_CREATED
            changed = True

        else:
            merged_data = resource.copy()
            merged_data.update(self.data)

            if ResourceComparator.compare(resource, merged_data):
                msg = FC_NETWORK_ALREADY_EXIST
            else:
                resource = self.oneview_client.fc_networks.update(merged_data)
                changed = True
                msg = FC_NETWORK_UPDATED

        return dict(
            msg=msg,
            changed=changed,
            ansible_facts=dict(fc_network=resource)
        )

    def __absent(self, resource):

        if resource:
            self.oneview_client.fc_networks.delete(resource)
            return {"changed": True, "msg": FC_NETWORK_DELETED}
        else:
            return {"changed": False, "msg": FC_NETWORK_ALREADY_ABSENT}

    def __get_by_name(self):
        result = self.oneview_client.fc_networks.get_by('name', self.data['name'])
        return result[0] if result else None


def main():
    FcNetworkModule().run()


if __name__ == '__main__':
    main()
