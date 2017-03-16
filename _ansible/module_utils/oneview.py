#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (2016) Hewlett Packard Enterprise Development LP
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.


from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)

from future import standard_library
from ansible.module_utils.basic import *
from copy import deepcopy
from collections import OrderedDict
import json
import logging

standard_library.install_aliases()
logger = logging.getLogger(__name__)

try:
    from hpOneView.oneview_client import OneViewClient
    from hpOneView.exceptions import (HPOneViewException,
                                      HPOneViewTaskError,
                                      HPOneViewValueError)

    HAS_HPE_ONEVIEW = True
except ImportError:
    HAS_HPE_ONEVIEW = False


class OneViewModuleBase(object):
    MSG_CREATED = 'Resource created successfully.'
    MSG_UPDATED = 'Resource updated successfully.'
    MSG_ALREADY_EXIST = 'Resource already exists.'
    MSG_DELETED = 'Resource deleted successfully.'
    MSG_ALREADY_ABSENT = 'Resource is already absent.'
    HPE_ONEVIEW_SDK_REQUIRED = 'HPE OneView Python SDK is required for this module.'

    RESOURCE_FACT_NAME = ''

    ONEVIEW_COMMON_ARGS = dict(
        config=dict(required=False, type='str')
    )

    ONEVIEW_VALIDATE_ETAG_ARGS = dict(
        validate_etag=dict(
            required=False,
            type='bool',
            default=True)
    )

    resource_client = None

    def __build_argument_spec(self, additional_arg_spec, validate_etag_support):

        merged_arg_spec = dict()
        merged_arg_spec.update(self.ONEVIEW_COMMON_ARGS)

        if validate_etag_support:
            merged_arg_spec.update(self.ONEVIEW_VALIDATE_ETAG_ARGS)

        if additional_arg_spec:
            merged_arg_spec.update(additional_arg_spec)

        return merged_arg_spec

    def __init__(self, additional_arg_spec=None, validate_etag_support=False):

        argument_spec = self.__build_argument_spec(additional_arg_spec, validate_etag_support)

        self.module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=False)

        self.__check_hpe_oneview()
        self.__create_oneview_client()

        self.state = self.module.params.get('state')
        self.data = self.module.params.get('data')
        self.validate_etag_support = validate_etag_support

    def __check_hpe_oneview(self):
        if not HAS_HPE_ONEVIEW:
            self.module.fail_json(msg=self.HPE_ONEVIEW_SDK_REQUIRED)

    def __create_oneview_client(self):
        if not self.module.params['config']:
            self.oneview_client = OneViewClient.from_environment_variables()
        else:
            self.oneview_client = OneViewClient.from_json_file(self.module.params['config'])

    def execute_module(self):
        # Abstract function, must be implemented by inheritor
        raise HPOneViewException("execute_module not implemented")

    def run(self):
        try:
            if self.validate_etag_support:
                if not self.module.params.get('validate_etag'):
                    self.oneview_client.connection.disable_etag_validation()

            result = self.execute_module()

            if "changed" not in result:
                result['changed'] = False

            self.module.exit_json(**result)

        except HPOneViewException as exception:
            self.module.fail_json(msg='; '.join(str(e) for e in exception.args))

    def resource_absent(self, resource, method='delete'):
        if resource:
            getattr(self.resource_client, method)(resource)

            return {"changed": True, "msg": self.MSG_DELETED}
        else:
            return {"changed": False, "msg": self.MSG_ALREADY_ABSENT}

    def get_by_name(self, name):
        result = self.resource_client.get_by('name', name)
        return result[0] if result else None

    def resource_present(self, resource, create_method='create'):

        if not self.RESOURCE_FACT_NAME:
            raise HPOneViewValueError("RESOURCE_FACT_NAME was not defined")

        changed = False
        if "newName" in self.data:
            self.data["name"] = self.data.pop("newName")

        if not resource:
            resource = getattr(self.resource_client, create_method)(self.data)
            msg = self.MSG_CREATED
            changed = True

        else:
            merged_data = resource.copy()
            merged_data.update(self.data)

            if ResourceComparator.compare(resource, merged_data):
                msg = self.MSG_ALREADY_EXIST
            else:
                resource = self.resource_client.update(merged_data)
                changed = True
                msg = self.MSG_UPDATED

        return dict(
            msg=msg,
            changed=changed,
            ansible_facts={self.RESOURCE_FACT_NAME: resource}
        )


class ResourceComparator():
    MSG_DIFF_AT_KEY = 'Difference found at key \'{0}\'. '

    @staticmethod
    def compare(first_resource, second_resource):
        """
        Recursively compares dictionary contents, ignoring type and order
        Args:
            first_resource: first dictionary
            second_resource: second dictionary

        Returns:
            bool: True when equal, False when different.
        """
        resource1 = deepcopy(first_resource)
        resource2 = deepcopy(second_resource)

        debug_resources = "resource1 = {0}, resource2 = {1}".format(resource1, resource2)

        # The first resource is True / Not Null and the second resource is False / Null
        if resource1 and not resource2:
            logger.debug("resource1 and not resource2. " + debug_resources)
            return False

        # Check all keys in first dict
        for key in resource1.keys():
            if key not in resource2:
                # no key in second dict
                if resource1[key] is not None:
                    # key inexistent is equivalent to exist and value None
                    logger.debug(ResourceComparator.MSG_DIFF_AT_KEY.format(key) + debug_resources)
                    return False
            # If both values are null / empty / False
            elif not resource1[key] and not resource2[key]:
                continue
            elif isinstance(resource1[key], dict):
                # recursive call
                if not ResourceComparator.compare(resource1[key], resource2[key]):
                    # if different, stops here
                    logger.debug(ResourceComparator.MSG_DIFF_AT_KEY.format(key) + debug_resources)
                    return False
            elif isinstance(resource1[key], list):
                # change comparison function (list compare)
                if not ResourceComparator.compare_list(resource1[key], resource2[key]):
                    # if different, stops here
                    logger.debug(ResourceComparator.MSG_DIFF_AT_KEY.format(key) + debug_resources)
                    return False
            elif ResourceComparator._standardize_value(resource1[key]) != ResourceComparator._standardize_value(
                    resource2[key]):
                # different value
                logger.debug(ResourceComparator.MSG_DIFF_AT_KEY.format(key) + debug_resources)
                return False

        # Check all keys in second dict to find missing
        for key in resource2.keys():
            if key not in resource1:
                # not exists in first dict
                if resource2[key] is not None:
                    # key inexistent is equivalent to exist and value None
                    logger.debug(ResourceComparator.MSG_DIFF_AT_KEY.format(key) + debug_resources)
                    return False

        # no differences found
        return True

    @staticmethod
    def compare_list(first_resource, second_resource):
        """
        Recursively compares lists contents, ignoring type
        Args:
            first_resource: first list
            second_resource: second list

        Returns:
            True when equal;
            False when different.

        """

        resource1 = deepcopy(first_resource)
        resource2 = deepcopy(second_resource)

        debug_resources = "resource1 = {0}, resource2 = {1}".format(resource1, resource2)

        # The second list is null / empty  / False
        if not resource2:
            logger.debug("resource 2 is null. " + debug_resources)
            return False

        if len(resource1) != len(resource2):
            # different length
            logger.debug("resources have different length. " + debug_resources)
            return False

        resource1 = sorted(resource1, key=ResourceComparator._str_sorted)
        resource2 = sorted(resource2, key=ResourceComparator._str_sorted)

        for i, val in enumerate(resource1):
            if isinstance(val, dict):
                # change comparison function
                if not ResourceComparator.compare(val, resource2[i]):
                    logger.debug("resources are different. " + debug_resources)
                    return False
            elif isinstance(val, list):
                # recursive call
                if not ResourceComparator.compare_list(val, resource2[i]):
                    logger.debug("lists are different. " + debug_resources)
                    return False
            elif ResourceComparator._standardize_value(val) != ResourceComparator._standardize_value(resource2[i]):
                # value is different
                logger.debug("values are different. " + debug_resources)
                return False

        # no differences found
        return True

    @staticmethod
    def _str_sorted(obj):
        if isinstance(obj, dict):
            return json.dumps(obj, sort_keys=True)
        else:
            return str(obj)

    @staticmethod
    def _standardize_value(value):
        """
        Convert value to string to enhance the comparison.

        Args:
            value: Any object type.

        Returns:
            str: Converted value.
        """
        if isinstance(value, float) and value.is_integer():
            # Workaround to avoid erroneous comparison between int and float
            # Removes zero from integer floats
            value = int(value)

        return str(value)


class ResourceMerger():
    @staticmethod
    def merge_list_by_key(original_list, updated_list, key, ignore_when_null=[]):
        """
        Merge two lists by the key. It basically:
        1. Adds the items that are present on updated_list and are absent on original_list.
        2. Removes items that are absent on updated_list and are present on original_list.
        3. For all items that are in both lists, overwrites the values from the original item by the updated item.

        Args:
            original_list: original list.
            updated_list: list with changes.
            key: unique identifier.
            ignore_when_null: list with the keys from the updated items that should be ignored in the merge, if its
            values are null.
        Returns:
            list: Lists merged.
        """
        if not original_list:
            return updated_list

        items_map = OrderedDict([(i[key], i.copy()) for i in original_list])

        merged_items = OrderedDict()

        for item in updated_list:
            item_key = item[key]
            if item_key in items_map:
                for ignored_key in ignore_when_null:
                    if ignored_key in item and not item[ignored_key]:
                        item.pop(ignored_key)
                merged_items[item_key] = items_map[item_key].copy()
                merged_items[item_key].update(item)
            else:
                merged_items[item_key] = item.copy()

        return [val for (_, val) in merged_items.items()]
