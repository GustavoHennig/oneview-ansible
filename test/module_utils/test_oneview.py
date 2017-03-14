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
import unittest
import mock

from _ansible.module_utils.oneview import (OneViewModuleBase,
                                           ResourceComparator,
                                           ResourceMerger,
                                           OneViewClient,
                                           HPOneViewException)

MSG_GENERIC_ERROR = 'Generic error message'
MSG_GENERIC = "Generic message"


class OneViewModuleBaseSpec(unittest.TestCase):
    """
    PreloadedMocksBaseTestCase provides the mocks used in this test case.
    """
    mock_ov_client_from_json_file = None
    mock_ov_client_from_env_vars = None
    mock_ansible_module = None
    mock_ansible_module_init = None
    mock_ov_client = None

    MODULE_EXECUTE_RETURN_VALUE = dict(
        changed=True,
        msg=MSG_GENERIC,
        ansible_facts={'ansible_facts': None}
    )

    PARAMS_FOR_PRESENT = dict(
        config='config.json',
        state='present',
        data={'name': 'resource name'}
    )

    def setUp(self):
        # Define OneView Client Mock (FILE)
        patcher_json_file = mock.patch.object(OneViewClient, 'from_json_file')
        self.addCleanup(patcher_json_file.stop)
        self.mock_ov_client_from_json_file = patcher_json_file.start()

        # Define OneView Client Mock
        self.mock_ov_client = self.mock_ov_client_from_json_file.return_value

        # Define OneView Client Mock (ENV)
        patcher_env = mock.patch.object(OneViewClient, 'from_environment_variables')
        self.addCleanup(patcher_env.stop)
        self.mock_ov_client_from_env_vars = patcher_env.start()

        # Define Ansible Module Mock
        patcher_ansible = mock.patch(OneViewModuleBase.__module__ + '.AnsibleModule')
        self.addCleanup(patcher_ansible.stop)
        self.mock_ansible_module_init = patcher_ansible.start()
        self.mock_ansible_module = mock.Mock()
        self.mock_ansible_module_init.return_value = self.mock_ansible_module

    def test_should_call_exit_json_properly(self):

        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT

        mock_run = mock.Mock()
        mock_run.return_value = self.MODULE_EXECUTE_RETURN_VALUE.copy()

        base_mod = OneViewModuleBase()
        base_mod.execute_module = mock_run
        base_mod.run()

        self.mock_ansible_module.exit_json.assert_called_once_with(
            changed=True,
            msg=MSG_GENERIC,
            ansible_facts={'ansible_facts': None}
        )

    def test_should_call_exit_json_adding_changed(self):

        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT

        mock_run = mock.Mock()
        mock_run.return_value = dict(
            msg=MSG_GENERIC,
            ansible_facts={'ansible_facts': None}
        )

        base_mod = OneViewModuleBase()
        base_mod.execute_module = mock_run
        base_mod.run()

        self.mock_ansible_module.exit_json.assert_called_once_with(
            changed=False,
            msg=MSG_GENERIC,
            ansible_facts={'ansible_facts': None}
        )

    def test_should_load_config_from_file(self):

        self.mock_ansible_module.params = {'config': 'config.json'}

        OneViewModuleBase()

        self.mock_ov_client_from_json_file.assert_called_once_with('config.json')
        self.mock_ov_client_from_env_vars.not_been_called()

    def test_should_load_config_from_environment(self):

        self.mock_ansible_module.params = {'config': None}

        OneViewModuleBase()

        self.mock_ov_client_from_env_vars.assert_called_once()
        self.mock_ov_client_from_json_file.not_been_called()

    def test_should_call_fail_json_when_not_have_oneview(self):
        self.mock_ansible_module.params = {'config': 'config.json'}

        with mock.patch(OneViewModuleBase.__module__ + ".HAS_HPE_ONEVIEW", False):
            OneViewModuleBase()

        self.mock_ansible_module.fail_json.assert_called_once_with(
            msg='HPE OneView Python SDK is required for this module.')

    def test_should_validate_etag_when_set_as_true(self):
        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT
        self.mock_ansible_module.params['validate_etag'] = True

        OneViewModuleBase(validate_etag_support=True).run()
        expected_arg_spec = {'config': {'required': False, 'type': 'str'},
                             'validate_etag': {'default': True, 'required': False, 'type': 'bool'}}
        self.mock_ansible_module_init.assert_called_once_with(argument_spec=expected_arg_spec,
                                                              supports_check_mode=False)
        self.mock_ov_client.connection.enable_etag_validation.not_been_called()
        self.mock_ov_client.connection.disable_etag_validation.not_been_called()

    def test_should_not_validate_etag_when_set_as_false(self):
        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT
        self.mock_ansible_module.params['validate_etag'] = False

        OneViewModuleBase(validate_etag_support=True).run()
        expected_arg_spec = {'config': {'required': False, 'type': 'str'},
                             'validate_etag': {'default': True, 'required': False, 'type': 'bool'}}
        self.mock_ansible_module_init.assert_called_once_with(argument_spec=expected_arg_spec,
                                                              supports_check_mode=False)
        self.mock_ov_client.connection.enable_etag_validation.not_been_called()
        self.mock_ov_client.connection.disable_etag_validation.assert_called_once()

    def test_should_not_validate_etag_when_not_supported(self):
        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT
        self.mock_ansible_module.params['validate_etag'] = False

        OneViewModuleBase(validate_etag_support=False).run()

        expected_arg_spec = {'config': {'required': False, 'type': 'str'}}
        self.mock_ansible_module_init.assert_called_once_with(argument_spec=expected_arg_spec,
                                                              supports_check_mode=False)

        self.mock_ov_client.connection.enable_etag_validation.not_been_called()
        self.mock_ov_client.connection.disable_etag_validation.not_been_called()

    def test_additional_argument_spec_construction(self):
        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT

        OneViewModuleBase(validate_etag_support=False, additional_arg_spec={'options': 'list'})

        expected_arg_spec = {'config': {'required': False, 'type': 'str'},
                             'options': 'list'}

        self.mock_ansible_module_init.assert_called_once_with(argument_spec=expected_arg_spec,
                                                              supports_check_mode=False)

    def test_should_call_fail_json_when_oneview_exception(self):
        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT

        mock_run = mock.Mock()
        mock_run.side_effect = HPOneViewException(MSG_GENERIC_ERROR)

        base_mod = OneViewModuleBase(validate_etag_support=True)
        base_mod.execute_module = mock_run
        base_mod.run()

        self.mock_ansible_module.fail_json.assert_called_once_with(msg=MSG_GENERIC_ERROR)

    def test_should_not_handle_value_error_exception(self):
        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT

        mock_run = mock.Mock()
        mock_run.side_effect = ValueError(MSG_GENERIC_ERROR)

        try:
            base_mod = OneViewModuleBase(validate_etag_support=True)
            base_mod.execute_module = mock_run
            base_mod.run()
        except ValueError as e:
            self.assertEqual(e.args[0], MSG_GENERIC_ERROR)
        else:
            self.fail('Expected ValueError was not raised')

    def test_should_not_handle_exception(self):
        self.mock_ansible_module.params = self.PARAMS_FOR_PRESENT

        mock_run = mock.Mock()
        mock_run.side_effect = Exception(MSG_GENERIC_ERROR)

        try:
            base_mod = OneViewModuleBase(validate_etag_support=True)
            base_mod.execute_module = mock_run
            base_mod.run()
        except Exception as e:
            self.assertEqual(e.args[0], MSG_GENERIC_ERROR)
        else:
            self.fail('Expected Exception was not raised')


class ResourceComparatorTest(unittest.TestCase):
    DICT_ORIGINAL = {u'status': u'OK', u'category': u'fcoe-networks',
                     u'description': None, u'created': u'2016-06-13T20:39:15.991Z',
                     u'uri': u'/rest/fcoe-networks/36c56106-3b14-4f0d-8df9-627700b8e01b',
                     u'state': u'Active',
                     u'vlanId': 201,
                     u'modified': u'2016-06-13T20:39:15.993Z',
                     u'fabricUri': u'/rest/fabrics/a3cff65e-6d95-4d4d-9047-3548b6aca902',
                     u'eTag': u'7275bfe5-2e41-426a-844a-9eb00ac8be41', u'managedSanUri': None,
                     u'connectionTemplateUri': u'/rest/connection-templates/0799d26c-68db-4b4c-b007-d31cf9d60a2f',
                     u'type': u'fcoe-network',
                     u"sub": {
                         "ssub": "ssub",
                         'fs_item': 1,
                         'level3': {
                             "lvl3_t1": "lvl3_t1"
                         },
                         "list": [1, 2, "3"]
                     },
                     u'name': u'Test FCoE Network'}

    DICT_EQUAL_ORIGINAL = {u'status': u'OK', u'category': u'fcoe-networks',
                           u'description': None, u'created': u'2016-06-13T20:39:15.991Z',
                           u'uri': u'/rest/fcoe-networks/36c56106-3b14-4f0d-8df9-627700b8e01b',
                           u'vlanId': '201',
                           "sub": {
                               "ssub": "ssub",
                               'fs_item': "1",
                               'level3': {
                                   "lvl3_t1": u"lvl3_t1"
                               },
                               "list": [1, '3', 2]
                           },
                           u'modified': u'2016-06-13T20:39:15.993Z',
                           u'fabricUri': u'/rest/fabrics/a3cff65e-6d95-4d4d-9047-3548b6aca902',
                           u'state': u'Active',
                           u'eTag': u'7275bfe5-2e41-426a-844a-9eb00ac8be41', u'managedSanUri': None,
                           u'connectionTemplateUri': u'/rest/connection-templates/0799d26c-68db-4b4c-b007-d31cf9d60a2f',
                           u'type': u'fcoe-network',
                           u'name': 'Test FCoE Network'}

    DICT_DIF_ORIGINAL_LV3 = {u'status': u'OK', u'category': u'fcoe-networks',
                             u'description': None, u'created': u'2016-06-13T20:39:15.991Z',
                             u'uri': u'/rest/fcoe-networks/36c56106-3b14-4f0d-8df9-627700b8e01b',
                             u'vlanId': '201',
                             "sub": {
                                 "ssub": "ssub",
                                 'fs_item': "1",
                                 'level3': {
                                     "lvl3_t1": u"lvl3_t1x"
                                 },
                                 "list": [1, 2, 3]
                             },
                             u'modified': u'2016-06-13T20:39:15.993Z',
                             u'fabricUri': u'/rest/fabrics/a3cff65e-6d95-4d4d-9047-3548b6aca902',
                             u'state': u'Active',
                             u'eTag': u'7275bfe5-2e41-426a-844a-9eb00ac8be41', u'managedSanUri': None,
                             u'connectionTemplateUri':
                                 u'/rest/connection-templates/0799d26c-68db-4b4c-b007-d31cf9d60a2f',
                             u'type': u'fcoe-network',
                             u'name': 'Test FCoE Network'}

    DICT_EMPTY_NONE1 = {
        "name": "Enclosure Group 1",
        "interconnectBayMappings":
            [
                {
                    "interconnectBay": 1,
                },
                {
                    "interconnectBay": 2,
                },
            ]
    }

    DICT_EMPTY_NONE2 = {
        "name": "Enclosure Group 1",
        "interconnectBayMappings":
            [
                {
                    "interconnectBay": 1,
                    'logicalInterconnectGroupUri': None
                },
                {
                    "interconnectBay": 2,
                    'logicalInterconnectGroupUri': None
                },
            ]
    }

    DICT_EMPTY_NONE3 = {
        "name": "Enclosure Group 1",
        "interconnectBayMappings":
            [
                {
                    "interconnectBay": 1,
                    'logicalInterconnectGroupUri': ''
                },
                {
                    "interconnectBay": 2,
                    'logicalInterconnectGroupUri': None
                },
            ]
    }

    def test_resource_compare_equals(self):
        self.assertTrue(ResourceComparator.compare(self.DICT_ORIGINAL, self.DICT_EQUAL_ORIGINAL))

    def test_resource_compare_missing_entry_in_first(self):
        dict1 = self.DICT_ORIGINAL.copy()
        del dict1['state']

        self.assertFalse(ResourceComparator.compare(dict1, self.DICT_EQUAL_ORIGINAL))

    def test_resource_compare_missing_entry_in_second(self):
        dict2 = self.DICT_EQUAL_ORIGINAL.copy()
        del dict2['state']

        self.assertFalse(ResourceComparator.compare(self.DICT_ORIGINAL, self.DICT_DIF_ORIGINAL_LV3))

    def test_resource_compare_different_on_level3(self):
        self.assertFalse(ResourceComparator.compare(self.DICT_ORIGINAL, self.DICT_DIF_ORIGINAL_LV3))

    def test_resource_compare_equals_with_empty_eq_none(self):
        self.assertTrue(ResourceComparator.compare(self.DICT_EMPTY_NONE1, self.DICT_EMPTY_NONE2))

    def test_resource_compare_equals_with_empty_eq_none_inverse(self):
        self.assertTrue(ResourceComparator.compare(self.DICT_EMPTY_NONE2, self.DICT_EMPTY_NONE1))

    def test_resource_compare_equals_with_empty_eq_none_different(self):
        self.assertFalse(ResourceComparator.compare(self.DICT_EMPTY_NONE3, self.DICT_EMPTY_NONE1))

    def test_resource_compare_with_double_level_list(self):
        dict1 = {list: [
            [1, 2, 3],
            [4, 5, 6]
        ]}

        dict2 = {list: [
            [1, 2, 3],
            [4, 5, "6"]
        ]}

        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_resource_compare_with_double_level_list_different(self):
        dict1 = {list: [
            [1, 2, 3],
            [4, 5, 6]
        ]}

        dict2 = {list: [
            [1, 2, 3],
            [4, 5, "7"]
        ]}

        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_with_int_and_float(self):
        dict1 = {
            "name": "name",
            "lvalue": int(10)
        }

        dict2 = {
            "name": "name",
            "lvalue": float(10)
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_with_str_and_integer_float(self):
        dict1 = {
            "name": "name",
            "lvalue": '10'
        }

        dict2 = {
            "name": "name",
            "lvalue": float(10)
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_with_str_and_float(self):
        dict1 = {
            "name": "name",
            "lvalue": '10.1'
        }

        dict2 = {
            "name": "name",
            "lvalue": float(10.1)
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_dict_and_list(self):
        dict1 = {
            "name": "name",
            "value": {"id": 123}
        }

        dict2 = {
            "name": "name",
            "value": [1, 2, 3]
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_list_and_dict(self):
        dict1 = {
            "name": "name",
            "value": [1, 2, 3]
        }

        dict2 = {
            "name": "name",
            "value": {"id": 123}
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_with_different_float_values(self):
        dict1 = {
            "name": "name",
            "lvalue": 10.2
        }

        dict2 = {
            "name": "name",
            "lvalue": float(10.1)
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_empty_list_and_none(self):
        dict1 = {
            "name": "name",
            "values": []
        }

        dict2 = {
            "name": "name",
            "values": None
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_none_and_empty_list(self):
        dict1 = {
            "name": "name",
            "values": None
        }
        dict2 = {
            "name": "name",
            "values": []
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_true_and_false(self):
        dict1 = {
            "name": "name",
            "values": True
        }

        dict2 = {
            "name": "name",
            "values": False
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_false_and_true(self):
        dict1 = {
            "name": "name",
            "values": False
        }

        dict2 = {
            "name": "name",
            "values": True
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_true_and_true(self):
        dict1 = {
            "name": "name",
            "values": True
        }

        dict2 = {
            "name": "name",
            "values": True
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_false_and_false(self):
        dict1 = {
            "name": "name",
            "values": False
        }

        dict2 = {
            "name": "name",
            "values": False
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_none_and_false(self):
        dict1 = {
            "name": "name",
            "values": None
        }

        dict2 = {
            "name": "name",
            "values": False
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_false_and_none(self):
        dict1 = {
            "name": "name",
            "values": False
        }
        dict2 = {
            "name": "name",
            "values": None
        }
        self.assertTrue(ResourceComparator.compare(dict1, dict2))

    def test_comparison_list_and_none_level_1(self):
        dict1 = {
            "name": "name of the resource",
            "value": [{"name": "item1"},
                      {"name": "item2"}]
        }
        dict2 = {
            "name": "name of the resource",
            "value": None
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_none_and_list_level_1(self):
        dict1 = {
            "name": "name",
            "value": None
        }
        dict2 = {
            "name": "name",
            "value": [{"name": "item1"},
                      {"name": "item2"}]
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_dict_and_none_level_1(self):
        dict1 = {
            "name": "name",
            "value": {"name": "subresource"}
        }
        dict2 = {
            "name": "name",
            "value": None
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_none_and_dict_level_1(self):
        dict1 = {
            "name": "name",
            "value": None
        }
        dict2 = {
            "name": "name",
            "value": {"name": "subresource"}
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_none_and_dict_level_2(self):
        dict1 = {
            "name": "name",
            "value": {"name": "subresource",
                      "value": None}
        }
        dict2 = {
            "name": "name",
            "value": {"name": "subresource",
                      "value": {
                          "name": "sub-sub-resource"
                      }}
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_dict_and_none_level_2(self):
        dict1 = {
            "name": "name",
            "value": {"name": "subresource",
                      "value": {
                          "name": "sub-sub-resource"
                      }}
        }
        dict2 = {
            "name": "name",
            "value": {"name": "subresource",
                      "value": None}
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_none_and_list_level_2(self):
        dict1 = {
            "name": "name",
            "value": {"name": "subresource",
                      "list": None}
        }
        dict2 = {
            "name": "name",
            "value": {"name": "subresource",
                      "list": ["item1", "item2"]}
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_list_and_none_level_2(self):
        dict1 = {
            "name": "name",
            "value": {"name": "subresource",
                      "list": ["item1", "item2"]}
        }
        dict2 = {
            "name": "name",
            "value": {"name": "subresource",
                      "list": None}
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))

    def test_comparison_list_of_dicts_with_diff_order(self):
        resource1 = {'connections': [
            {
                u'allocatedMbps': 0,
                u'networkUri': u'/rest/fc-networks/617a2c3b-1505-4369-a0a5-4c169183bf9d',
                u'requestedMbps': u'2500',
                u'portId': u'None',
                u'name': u'connection2',
                u'maximumMbps': 0,
                u'wwpnType': u'Virtual',
                u'deploymentStatus': u'Reserved',
                u'boot': {
                    u'priority': u'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'wwnn': u'10:00:c2:54:96:f0:00:03',
                u'mac': u'46:E0:32:50:00:01',
                u'macType': u'Virtual',
                u'wwpn': u'10:00:c2:54:96:f0:00:02',
                u'interconnectUri': None,
                u'requestedVFs': None,
                u'functionType': u'FibreChannel',
                u'id': 2,
                u'allocatedVFs': None
            },
            {
                u'allocatedMbps': 1000,
                u'networkUri': u'/rest/ethernet-networks/7704a66f-fa60-4375-8e9d-e72111bf4b3a',
                u'requestedMbps': u'1000',
                u'portId': u'Flb 1:1-a',
                u'name': u'connection3',
                u'maximumMbps': 1000,
                u'wwpnType': u'Virtual',
                u'deploymentStatus': u'Deployed',
                u'boot': {
                    u'priority': u'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'wwnn': None,
                u'mac': u'46:E0:32:50:00:02',
                u'macType': u'Virtual',
                u'wwpn': None,
                u'interconnectUri': u'/rest/interconnects/6930962f-8aba-42ac-8bbc-3794890ea945',
                u'requestedVFs': u'Auto',
                u'functionType': u'Ethernet',
                u'id': 3,
                u'allocatedVFs': None
            },
            {
                u'allocatedMbps': 1000,
                u'networkUri': u'/rest/ethernet-networks/7704a66f-fa60-4375-8e9d-e72111bf4b3a',
                u'requestedMbps': u'1000',
                u'portId': u'Flb 1:2-a',
                u'name': u'connection4',
                u'maximumMbps': 1000,
                u'wwpnType': u'Virtual',
                u'deploymentStatus': u'Deployed',
                u'boot': {
                    u'priority': u'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'wwnn': None,
                u'mac': u'46:E0:32:50:00:03',
                u'macType': u'Virtual',
                u'wwpn': None,
                u'interconnectUri': u'/rest/interconnects/a3c936f2-2993-4779-a6e3-dc302b6f1bc6',
                u'requestedVFs': u'Auto',
                u'functionType': u'Ethernet',
                u'id': 4,
                u'allocatedVFs': None
            },
            {
                u'allocatedMbps': 2500,
                u'networkUri': u'/rest/fc-networks/179222e0-d59e-4898-b2bf-5c053c872ee6',
                u'requestedMbps': u'2500',
                u'portId': u'Flb 1:1-b',
                u'name': u'connection1',
                u'maximumMbps': 10000,
                u'wwpnType': u'Virtual',
                u'deploymentStatus': u'Deployed',
                u'boot': {
                    u'priority': u'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'wwnn': u'10:00:c2:54:96:f0:00:01',
                u'mac': u'46:E0:32:50:00:00',
                u'macType': u'Virtual',
                u'wwpn': u'10:00:c2:54:96:f0:00:00',
                u'interconnectUri': u'/rest/interconnects/6930962f-8aba-42ac-8bbc-3794890ea945',
                u'requestedVFs': None,
                u'functionType': u'FibreChannel',
                u'id': 1,
                u'allocatedVFs': None
            }
        ]
        }

        resource2 = {'connections': [
            {
                u'requestedMbps': 1000,
                u'deploymentStatus': u'Deployed',
                u'networkUri': u'/rest/ethernet-networks/7704a66f-fa60-4375-8e9d-e72111bf4b3a',
                u'mac': u'46:E0:32:50:00:02',
                u'wwpnType': u'Virtual',
                u'id': 3,
                u'macType': u'Virtual',
                u'allocatedMbps': 1000,
                u'wwnn': None,
                u'maximumMbps': 1000,
                u'portId': u'Flb 1:1-a',
                u'name': 'connection3',
                u'functionType': 'Ethernet',
                u'boot': {
                    u'priority': 'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'allocatedVFs': None,
                u'wwpn': None,
                u'interconnectUri': u'/rest/interconnects/6930962f-8aba-42ac-8bbc-3794890ea945',
                u'requestedVFs': u'Auto'
            },
            {
                u'requestedMbps': 1000,
                u'deploymentStatus': u'Deployed',
                u'networkUri': u'/rest/ethernet-networks/7704a66f-fa60-4375-8e9d-e72111bf4b3a',
                u'mac': u'46:E0:32:50:00:03',
                u'wwpnType': u'Virtual',
                u'id': 4,
                u'macType': u'Virtual',
                u'allocatedMbps': 1000,
                u'wwnn': None,
                u'maximumMbps': 1000,
                u'portId': u'Flb 1:2-a',
                u'name': 'connection4',
                u'functionType': 'Ethernet',
                u'boot': {
                    u'priority': 'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'allocatedVFs': None,
                u'wwpn': None,
                u'interconnectUri': u'/rest/interconnects/a3c936f2-2993-4779-a6e3-dc302b6f1bc6',
                u'requestedVFs': u'Auto'
            },
            {
                u'requestedMbps': 2500,
                u'deploymentStatus': u'Deployed',
                u'networkUri': u'/rest/fc-networks/179222e0-d59e-4898-b2bf-5c053c872ee6',
                u'mac': u'46:E0:32:50:00:00',
                u'wwpnType': u'Virtual',
                u'id': 1,
                u'macType': u'Virtual',
                u'allocatedMbps': 2500,
                u'wwnn': u'10:00:c2:54:96:f0:00:01',
                u'maximumMbps': 10000,
                u'portId': u'Flb 1:1-b',
                u'name': 'connection1',
                u'functionType': 'FibreChannel',
                u'boot': {
                    u'priority': 'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'allocatedVFs': None,
                u'wwpn': u'10:00:c2:54:96:f0:00:00',
                u'interconnectUri': u'/rest/interconnects/6930962f-8aba-42ac-8bbc-3794890ea945',
                u'requestedVFs': None
            },
            {
                u'requestedMbps': 2500,
                u'deploymentStatus': u'Reserved',
                u'networkUri': u'/rest/fc-networks/617a2c3b-1505-4369-a0a5-4c169183bf9d',
                u'mac': u'46:E0:32:50:00:01',
                u'wwpnType': u'Virtual',
                u'id': 2,
                u'macType': u'Virtual',
                u'allocatedMbps': 0,
                u'wwnn': u'10:00:c2:54:96:f0:00:03',
                u'maximumMbps': 0,
                u'portId': 'None',
                u'name': 'connection2',
                u'functionType': 'FibreChannel',
                u'boot': {
                    u'priority': 'NotBootable',
                    u'chapLevel': u'None',
                    u'initiatorNameSource': u'ProfileInitiatorName'
                },
                u'allocatedVFs': None,
                u'wwpn': u'10:00:c2:54:96:f0:00:02',
                u'interconnectUri': None,
                u'requestedVFs': None
            }
        ]
        }

        self.assertTrue(ResourceComparator.compare(resource1, resource2))

    def test_comparison_list_when_dict_has_diff_key(self):
        dict1 = {
            "name": "name",
            "value": [{'name': 'value1'},
                      {'name': 'value2'},
                      {'name': 3}]
        }

        dict2 = {
            "name": "name",
            "value": [{'count': 3},
                      {'name': 'value1'},
                      {'name': 'value2'}]
        }
        self.assertFalse(ResourceComparator.compare(dict1, dict2))


class ResourceMergerTest(unittest.TestCase):
    def test_merge_list_by_key_when_original_list_is_empty(self):
        original_list = []
        list_with_changes = [dict(id=1, value="123")]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id")

        expected_list = [dict(id=1, value="123")]
        self.assertEqual(merged_list, expected_list)

    def test_merge_list_by_key_when_original_list_is_null(self):
        original_list = None
        list_with_changes = [dict(id=1, value="123")]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id")

        expected_list = [dict(id=1, value="123")]
        self.assertEqual(merged_list, expected_list)

    def test_merge_list_by_key_with_same_lenght_and_order(self):
        original_list = [dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=3500),
                         dict(id=2, allocatedMbps=1000, mac="E2:4B:0D:30:00:0B", requestedMbps=1000)]

        list_with_changes = [dict(id=1, requestedMbps=2700, allocatedVFs=3500),
                             dict(id=2, requestedMbps=1005)]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id")

        expected_list = [dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=2700, allocatedVFs=3500),
                         dict(id=2, allocatedMbps=1000, mac="E2:4B:0D:30:00:0B", requestedMbps=1005)]

        self.assertEqual(merged_list, expected_list)

    def test_merge_list_by_key_with_different_order(self):
        original_list = [dict(id=2, allocatedMbps=1000, mac="E2:4B:0D:30:00:0B", requestedMbps=1000),
                         dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=3500)]

        list_with_changes = [dict(id=1, requestedMbps=2700, allocatedVFs=3500),
                             dict(id=2, requestedMbps=1005)]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id")

        expected_list = [dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=2700, allocatedVFs=3500),
                         dict(id=2, allocatedMbps=1000, mac="E2:4B:0D:30:00:0B", requestedMbps=1005)]

        self.assertEqual(merged_list, expected_list)

    def test_merge_list_by_key_with_removed_items(self):
        original_list = [dict(id=2, allocatedMbps=1000, mac="E2:4B:0D:30:00:0B", requestedMbps=1000),
                         dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=3500)]

        list_with_changes = [dict(id=1, requestedMbps=2700, allocatedVFs=3500)]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id")

        expected_list = [dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=2700, allocatedVFs=3500)]

        self.assertEqual(merged_list, expected_list)

    def test_merge_list_by_key_with_added_items(self):
        original_list = [dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=3500)]

        list_with_changes = [dict(id=1, requestedMbps=2700, allocatedVFs=3500),
                             dict(id=2, requestedMbps=1005)]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id")

        expected_list = [dict(id=1, allocatedMbps=2500, mac="E2:4B:0D:30:00:09", requestedMbps=2700, allocatedVFs=3500),
                         dict(id=2, requestedMbps=1005)]

        self.assertEqual(merged_list, expected_list)

    def test_merge_list_by_key_should_ignore_key_when_null(self):
        original_list = [dict(id=1, value1="123", value2="345")]
        list_with_changes = [dict(id=1, value1=None, value2="345-changed")]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id",
                                                       ignore_when_null=['value1', 'value2'])

        expected_list = [dict(id=1, value1="123", value2="345-changed")]

        self.assertEqual(merged_list, expected_list)

    def test_merge_list_by_key_should_not_fail_when_ignored_key_absent(self):
        original_list = [dict(id=1, value1="123", value2="345")]
        list_with_changes = [dict(id=1, value3="678")]

        merged_list = ResourceMerger.merge_list_by_key(original_list, list_with_changes, key="id",
                                                       ignore_when_null=['value1'])

        expected_list = [dict(id=1, value1="123", value2="345", value3="678")]

        self.assertEqual(merged_list, expected_list)


if __name__ == '__main__':
    unittest.main()
