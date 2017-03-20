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
import json
import logging
import os
from ansible.module_utils.basic import AnsibleModule
from copy import deepcopy
from collections import OrderedDict

standard_library.install_aliases()
logger = logging.getLogger(__name__)

try:
    from hpOneView.oneview_client import OneViewClient
    from hpOneView.exceptions import (HPOneViewException,
                                      HPOneViewTaskError,
                                      HPOneViewValueError,
                                      HPOneViewResourceNotFound)

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

        # Preload params for get_all - used by facts
        self.params = self.module.params.get('params') or {}

        # Preload options as dict - used by facts
        self.options = self.transform_list_to_dict(self.module.params.get('options'))

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

    @staticmethod
    def transform_list_to_dict(list_):
        """
            Transforms a list into a dictionary, putting values as keys
        Args:
            list_: List of values

        Returns:
            dict: dictionary built
        """

        ret = {}

        if not list_:
            return ret

        for value in list_:
            if isinstance(value, dict):
                ret.update(value)
            else:
                ret[str(value)] = True

        return ret

    @staticmethod
    def get_logger(mod_name):
        """
            To activate logs, setup the environment var LOGFILE
            e.g.: export LOGFILE=/tmp/ansible-oneview.log
        Args:
            mod_name: module name

        Returns: Logger instance
        """

        logger = logging.getLogger(os.path.basename(mod_name))
        global LOGFILE
        LOGFILE = os.environ.get('LOGFILE')
        if not LOGFILE:
            logger.addHandler(logging.NullHandler())
        else:
            logging.basicConfig(level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S',
                                format='%(asctime)s %(levelname)s %(name)s %(message)s',
                                filename=LOGFILE, filemode='a')
        return logger


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


class SPKeys(object):
    ID = 'id'
    NAME = 'name'
    DEVICE_SLOT = 'deviceSlot'
    CONNECTIONS = 'connections'
    OS_DEPLOYMENT = 'osDeploymentSettings'
    OS_DEPLOYMENT_URI = 'osDeploymentPlanUri'
    ATTRIBUTES = 'osCustomAttributes'
    SAN = 'sanStorage'
    VOLUMES = 'volumeAttachments'
    PATHS = 'storagePaths'
    CONN_ID = 'connectionId'
    BOOT = 'boot'
    BIOS = 'bios'
    BOOT_MODE = 'bootMode'
    LOCAL_STORAGE = 'localStorage'
    SAS_LOGICAL_JBODS = 'sasLogicalJBODs'
    CONTROLLERS = 'controllers'
    LOGICAL_DRIVES = 'logicalDrives'
    SAS_LOGICAL_JBOD_URI = 'sasLogicalJBODUri'
    SAS_LOGICAL_JBOD_ID = 'sasLogicalJBODId'
    MODE = 'mode'
    MAC_TYPE = 'macType'
    MAC = 'mac'
    SERIAL_NUMBER_TYPE = 'serialNumberType'
    UUID = 'uuid'
    SERIAL_NUMBER = 'serialNumber'
    DRIVE_NUMBER = 'driveNumber'
    WWPN_TYPE = 'wwpnType'
    WWNN = 'wwnn'
    WWPN = 'wwpn'
    LUN_TYPE = 'lunType'
    LUN = 'lun'


class ServerProfileMerger(object):
    def merge_data(self, resource, data):
        merged_data = deepcopy(resource)
        merged_data.update(data)

        merged_data = self._merge_bios_and_boot(merged_data, resource, data)
        merged_data = self._merge_connections(merged_data, resource, data)
        merged_data = self._merge_san_storage(merged_data, data, resource)
        merged_data = self._merge_os_deployment_settings(merged_data, resource, data)
        merged_data = self._merge_local_storage(merged_data, resource, data)

        return merged_data

    def _merge_bios_and_boot(self, merged_data, resource, data):
        if self._should_merge(data, resource, key=SPKeys.BIOS):
            merged_data = self._merge_dict(merged_data, resource, data, key=SPKeys.BIOS)
        if self._should_merge(data, resource, key=SPKeys.BOOT):
            merged_data = self._merge_dict(merged_data, resource, data, key=SPKeys.BOOT)
        if self._should_merge(data, resource, key=SPKeys.BOOT_MODE):
            merged_data = self._merge_dict(merged_data, resource, data, key=SPKeys.BOOT_MODE)
        return merged_data

    def _merge_connections(self, merged_data, resource, data):
        if self._should_merge(data, resource, key=SPKeys.CONNECTIONS):
            existing_connections = resource[SPKeys.CONNECTIONS]
            params_connections = data[SPKeys.CONNECTIONS]
            merged_data[SPKeys.CONNECTIONS] = ResourceMerger.merge_list_by_key(existing_connections,
                                                                               params_connections,
                                                                               key=SPKeys.ID)

            # merge Boot from Connections
            merged_data = self._merge_connections_boot(merged_data, resource)
        return merged_data

    def _merge_connections_boot(self, merged_data, resource):
        existing_connection_map = {x[SPKeys.ID]: x.copy() for x in resource[SPKeys.CONNECTIONS]}
        for merged_connection in merged_data[SPKeys.CONNECTIONS]:
            conn_id = merged_connection[SPKeys.ID]
            existing_conn_has_boot = conn_id in existing_connection_map and SPKeys.BOOT in existing_connection_map[
                conn_id]
            if existing_conn_has_boot and SPKeys.BOOT in merged_connection:
                current_connection = existing_connection_map[conn_id]
                boot_settings_merged = deepcopy(current_connection[SPKeys.BOOT])
                boot_settings_merged.update(merged_connection[SPKeys.BOOT])
                merged_connection[SPKeys.BOOT] = boot_settings_merged
        return merged_data

    def _merge_san_storage(self, merged_data, data, resource):
        if self._removed_data(data, resource, key=SPKeys.SAN):
            merged_data[SPKeys.SAN] = dict(volumeAttachments=[], manageSanStorage=False)
        elif self._should_merge(data, resource, key=SPKeys.SAN):
            merged_data = self._merge_dict(merged_data, resource, data, key=SPKeys.SAN)

            # Merge Volumes from SAN Storage
            merged_data = self._merge_san_volumes(merged_data, resource, data)
        return merged_data

    def _merge_san_volumes(self, merged_data, resource, data):
        if self._should_merge(data[SPKeys.SAN], resource[SPKeys.SAN], key=SPKeys.VOLUMES):
            existing_volumes = resource[SPKeys.SAN][SPKeys.VOLUMES]
            params_volumes = data[SPKeys.SAN][SPKeys.VOLUMES]
            merged_volumes = ResourceMerger.merge_list_by_key(existing_volumes, params_volumes, key=SPKeys.ID)
            merged_data[SPKeys.SAN][SPKeys.VOLUMES] = merged_volumes

            # Merge Paths from SAN Storage Volumes
            merged_data = self._merge_san_storage_paths(merged_data, resource)
        return merged_data

    def _merge_san_storage_paths(self, merged_data, resource):

        existing_volumes_map = OrderedDict([(i[SPKeys.ID], i) for i in resource[SPKeys.SAN][SPKeys.VOLUMES]])
        merged_volumes = merged_data[SPKeys.SAN][SPKeys.VOLUMES]
        for merged_volume in merged_volumes:
            volume_id = merged_volume[SPKeys.ID]
            if volume_id in existing_volumes_map:
                if SPKeys.PATHS in merged_volume and SPKeys.PATHS in existing_volumes_map[volume_id]:
                    existent_paths = existing_volumes_map[volume_id][SPKeys.PATHS]

                    paths_from_merged_volume = merged_volume[SPKeys.PATHS]

                    merged_paths = ResourceMerger.merge_list_by_key(existent_paths,
                                                                    paths_from_merged_volume,
                                                                    key=SPKeys.CONN_ID)

                    merged_volume[SPKeys.PATHS] = merged_paths
        return merged_data

    def _merge_os_deployment_settings(self, merged_data, resource, data):
        if self._should_merge(data, resource, key=SPKeys.OS_DEPLOYMENT):
            merged_data = self._merge_dict(merged_data, resource, data, key=SPKeys.OS_DEPLOYMENT)

            # Merge Custom Attributes from OS Deployment Settings
            merged_data = self._merge_os_deployment_custom_attr(merged_data, resource, data)
        return merged_data

    def _merge_os_deployment_custom_attr(self, merged_data, resource, data):
        from hpOneView.extras.comparators import resource_compare_list

        if SPKeys.ATTRIBUTES in data[SPKeys.OS_DEPLOYMENT]:
            existing_os_deployment = resource[SPKeys.OS_DEPLOYMENT]
            params_os_deployment = data[SPKeys.OS_DEPLOYMENT]
            merged_os_deployment = merged_data[SPKeys.OS_DEPLOYMENT]

            if self._removed_data(params_os_deployment, existing_os_deployment, key=SPKeys.ATTRIBUTES):
                merged_os_deployment[SPKeys.ATTRIBUTES] = params_os_deployment[SPKeys.ATTRIBUTES]
            else:
                existing_attributes = existing_os_deployment[SPKeys.ATTRIBUTES]
                params_attributes = params_os_deployment[SPKeys.ATTRIBUTES]

                if resource_compare_list(existing_attributes, params_attributes):
                    merged_os_deployment[SPKeys.ATTRIBUTES] = existing_attributes

        return merged_data

    def _merge_local_storage(self, merged_data, resource, data):
        if self._removed_data(data, resource, key=SPKeys.LOCAL_STORAGE):
            merged_data[SPKeys.LOCAL_STORAGE] = dict(sasLogicalJBODs=[], controllers=[])
        elif self._should_merge(data, resource, key=SPKeys.LOCAL_STORAGE):
            # Merge SAS Logical JBODs from Local Storage
            merged_data = self._merge_sas_logical_jbods(merged_data, resource, data)
            # Merge Controllers from Local Storage
            merged_data = self._merge_controllers(merged_data, resource, data)
        return merged_data

    def _merge_sas_logical_jbods(self, merged_data, resource, data):
        if self._should_merge(data[SPKeys.LOCAL_STORAGE], resource[SPKeys.LOCAL_STORAGE], key=SPKeys.SAS_LOGICAL_JBODS):
            existing_items = resource[SPKeys.LOCAL_STORAGE][SPKeys.SAS_LOGICAL_JBODS]
            provided_items = merged_data[SPKeys.LOCAL_STORAGE][SPKeys.SAS_LOGICAL_JBODS]
            merged_jbods = ResourceMerger.merge_list_by_key(existing_items,
                                                            provided_items,
                                                            key=SPKeys.ID,
                                                            ignore_when_null=[SPKeys.SAS_LOGICAL_JBOD_URI])
            merged_data[SPKeys.LOCAL_STORAGE][SPKeys.SAS_LOGICAL_JBODS] = merged_jbods
        return merged_data

    def _merge_controllers(self, merged_data, resource, data):
        if self._should_merge(data[SPKeys.LOCAL_STORAGE], resource[SPKeys.LOCAL_STORAGE], key=SPKeys.CONTROLLERS):
            existing_items = resource[SPKeys.LOCAL_STORAGE][SPKeys.CONTROLLERS]
            provided_items = merged_data[SPKeys.LOCAL_STORAGE][SPKeys.CONTROLLERS]
            merged_controllers = ResourceMerger.merge_list_by_key(existing_items,
                                                                  provided_items,
                                                                  key=SPKeys.DEVICE_SLOT)
            merged_data[SPKeys.LOCAL_STORAGE][SPKeys.CONTROLLERS] = merged_controllers

            # Merge Drives from Mezzanine and Embedded controllers
            merged_data = self._merge_controller_drives(merged_data, resource)
        return merged_data

    def _merge_controller_drives(self, merged_data, resource):
        for current_controller in merged_data[SPKeys.LOCAL_STORAGE][SPKeys.CONTROLLERS][:]:
            for existing_controller in resource[SPKeys.LOCAL_STORAGE][SPKeys.CONTROLLERS][:]:
                same_slot = current_controller.get(SPKeys.DEVICE_SLOT) == existing_controller.get(SPKeys.DEVICE_SLOT)
                same_mode = existing_controller.get(SPKeys.MODE) == existing_controller.get(SPKeys.MODE)
                if same_slot and same_mode and current_controller[SPKeys.LOGICAL_DRIVES]:

                    key_merge = self._define_key_to_merge_drives(current_controller)

                    if key_merge:
                        merged_drives = ResourceMerger.merge_list_by_key(existing_controller[SPKeys.LOGICAL_DRIVES],
                                                                         current_controller[SPKeys.LOGICAL_DRIVES],
                                                                         key=key_merge)
                        current_controller[SPKeys.LOGICAL_DRIVES] = merged_drives
        return merged_data

    def _define_key_to_merge_drives(self, controller):
        has_name = True
        has_logical_jbod_id = True
        for drive in controller[SPKeys.LOGICAL_DRIVES]:
            if not drive.get(SPKeys.NAME):
                has_name = False
            if not drive.get(SPKeys.SAS_LOGICAL_JBOD_ID):
                has_logical_jbod_id = False

        if has_name:
            return SPKeys.NAME
        elif has_logical_jbod_id:
            return SPKeys.SAS_LOGICAL_JBOD_ID
        return None

    def _removed_data(self, data, resource, key):
        return key in data and not data[key] and key in resource

    def _should_merge(self, data, resource, key):
        data_has_value = key in data and data[key]
        existing_resource_has_value = key in resource and resource[key]
        return data_has_value and existing_resource_has_value

    def _merge_dict(self, merged_data, resource, data, key):
        if resource[key]:
            merged_dict = deepcopy(resource[key])
            merged_dict.update(deepcopy(data[key]))
        merged_data[key] = merged_dict
        return merged_data


class ServerProfileReplaceNamesByUris(object):
    SERVER_PROFILE_OS_DEPLOYMENT_NOT_FOUND = 'OS Deployment Plan not found: '
    SERVER_PROFILE_ENCLOSURE_GROUP_NOT_FOUND = 'Enclosure Group not found: '
    SERVER_PROFILE_NETWORK_NOT_FOUND = 'Network not found: '
    SERVER_HARDWARE_TYPE_NOT_FOUND = 'Server Hardware Type not found: '
    VOLUME_NOT_FOUND = 'Volume not found: '
    STORAGE_POOL_NOT_FOUND = 'Storage Pool not found: '
    STORAGE_SYSTEM_NOT_FOUND = 'Storage System not found: '
    INTERCONNECT_NOT_FOUND = 'Interconnect not found: '
    FIRMWARE_DRIVER_NOT_FOUND = 'Firmware Driver not found: '
    SAS_LOGICAL_JBOD_NOT_FOUND = 'SAS logical JBOD not found: '
    ENCLOSURE_NOT_FOUND = 'Enclosure not found: '

    def replace(self, oneview_client, data):
        self.oneview_client = oneview_client
        self.__replace_os_deployment_name_by_uri(data)
        self.__replace_enclosure_group_name_by_uri(data)
        self.__replace_networks_name_by_uri(data)
        self.__replace_server_hardware_type_name_by_uri(data)
        self.__replace_volume_attachment_names_by_uri(data)
        self.__replace_enclosure_name_by_uri(data)
        self.__replace_interconnect_name_by_uri(data)
        self.__replace_firmware_baseline_name_by_uri(data)
        self.__replace_sas_logical_jbod_name_by_uri(data)

    def __replace_name_by_uri(self, data, attr_name, message, resource_client):
        attr_uri = attr_name.replace("Name", "Uri")
        if attr_name in data:
            name = data.pop(attr_name)
            resource_by_name = resource_client.get_by('name', name)
            if not resource_by_name:
                raise HPOneViewResourceNotFound(message + name)
            data[attr_uri] = resource_by_name[0]['uri']

    def __replace_os_deployment_name_by_uri(self, data):
        if SPKeys.OS_DEPLOYMENT in data and data[SPKeys.OS_DEPLOYMENT]:
            self.__replace_name_by_uri(data[SPKeys.OS_DEPLOYMENT], 'osDeploymentPlanName',
                                       self.SERVER_PROFILE_OS_DEPLOYMENT_NOT_FOUND,
                                       self.oneview_client.os_deployment_plans)

    def __replace_enclosure_group_name_by_uri(self, data):
        self.__replace_name_by_uri(data, 'enclosureGroupName', self.SERVER_PROFILE_ENCLOSURE_GROUP_NOT_FOUND,
                                   self.oneview_client.enclosure_groups)

    def __replace_networks_name_by_uri(self, data):
        if SPKeys.CONNECTIONS in data and data[SPKeys.CONNECTIONS]:
            for connection in data[SPKeys.CONNECTIONS]:
                if 'networkName' in connection:
                    name = connection.pop('networkName', None)
                    connection['networkUri'] = self.__get_network_by_name(name)['uri']

    def __replace_server_hardware_type_name_by_uri(self, data):
        self.__replace_name_by_uri(data, 'serverHardwareTypeName', self.SERVER_HARDWARE_TYPE_NOT_FOUND,
                                   self.oneview_client.server_hardware_types)

    def __replace_volume_attachment_names_by_uri(self, data):
        volume_attachments = (data.get('sanStorage') or {}).get('volumeAttachments') or []
        if len(volume_attachments) > 0:
            for volume in volume_attachments:
                self.__replace_name_by_uri(volume, 'volumeName', self.VOLUME_NOT_FOUND, self.oneview_client.volumes)
                self.__replace_name_by_uri(volume, 'volumeStoragePoolName', self.STORAGE_POOL_NOT_FOUND,
                                           self.oneview_client.storage_pools)
                self.__replace_name_by_uri(volume, 'volumeStorageSystemName', self.STORAGE_SYSTEM_NOT_FOUND,
                                           self.oneview_client.storage_systems)

    def __replace_enclosure_name_by_uri(self, data):
        self.__replace_name_by_uri(data, 'enclosureName', self.ENCLOSURE_NOT_FOUND, self.oneview_client.enclosures)

    def __replace_interconnect_name_by_uri(self, data):
        connections = data.get('connections') or []
        if len(connections) > 0:
            for connection in connections:
                self.__replace_name_by_uri(connection, 'interconnectName', self.INTERCONNECT_NOT_FOUND,
                                           self.oneview_client.interconnects)

    def __replace_firmware_baseline_name_by_uri(self, data):
        firmware = data.get('firmware') or {}
        self.__replace_name_by_uri(firmware, 'firmwareBaselineName', self.FIRMWARE_DRIVER_NOT_FOUND,
                                   self.oneview_client.firmware_drivers)

    def __replace_sas_logical_jbod_name_by_uri(self, data):
        sas_logical_jbods = (data.get('localStorage') or {}).get('sasLogicalJBODs') or []
        if len(sas_logical_jbods) > 0:
            for jbod in sas_logical_jbods:
                self.__replace_name_by_uri(jbod, 'sasLogicalJBODName', self.SAS_LOGICAL_JBOD_NOT_FOUND,
                                           self.oneview_client.sas_logical_jbods)

    def __get_network_by_name(self, name):
        fc_networks = self.oneview_client.fc_networks.get_by('name', name)
        if fc_networks:
            return fc_networks[0]

        ethernet_networks = self.oneview_client.ethernet_networks.get_by('name', name)
        if not ethernet_networks:
            raise HPOneViewResourceNotFound(self.SERVER_PROFILE_NETWORK_NOT_FOUND + name)
        return ethernet_networks[0]
