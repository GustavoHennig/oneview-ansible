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

import importlib

from mock import Mock, patch
from hpOneView.oneview_client import OneViewClient


class OneViewBaseTestCase(object):
    mock_ov_client_from_json_file = None
    testing_class = None
    mock_ansible_module = None
    mock_ov_client = None

    def configure_mocks(self, test_case, testing_class):
        """
        Preload mocked OneViewClient instance and AnsibleModule
        Args:
            test_case (object): class instance (self) that are inheriting from ModuleContructorTestCase
            testing_class (object): class being tested
        """
        self.testing_class = testing_class

        # Define OneView Client Mock (FILE)
        patcher_json_file = patch.object(OneViewClient, 'from_json_file')
        test_case.addCleanup(patcher_json_file.stop)
        self.mock_ov_client_from_json_file = patcher_json_file.start()

        # Define OneView Client Mock
        self.mock_ov_client = self.mock_ov_client_from_json_file.return_value

        # Define Ansible Module Mock
        patcher_ansible = patch('_ansible.module_utils.oneview.AnsibleModule')
        test_case.addCleanup(patcher_ansible.stop)
        mock_ansible_module = patcher_ansible.start()
        self.mock_ansible_module = Mock()
        mock_ansible_module.return_value = self.mock_ansible_module

    def test_main_function_should_call_run_method(self):
        self.mock_ansible_module.params = {'config': 'config.json'}

        module = importlib.import_module(self.testing_class.__module__)
        main_func = getattr(module, 'main')

        with patch.object(self.testing_class, "run") as mock_run:
            main_func()
            mock_run.assert_called_once()


class FactsParamsTestCase(OneViewBaseTestCase):
    """
    FactsParamsTestCase has common test for classes that support pass additional
        parameters when retrieving all resources.
    """

    def configure_client_mock(self, resorce_client):
        """
        Args:
             resorce_client: Resource client that is being called
        """
        self.resource_client = resorce_client

    def __validations(self):
        if not self.testing_class:
            raise Exception("Mocks are not configured, you must call 'configure_mocks' before running this test.")

        if not self.resource_client:
            raise Exception(
                "Mock for the client not configured, you must call 'configure_client_mock' before running this test.")

    def test_should_get_all_using_filters(self):
        self.__validations()
        self.resource_client.get_all.return_value = []

        params_get_all_with_filters = dict(
            config='config.json',
            name=None,
            params={
                'start': 1,
                'count': 3,
                'sort': 'name:descending',
                'filter': 'purpose=General',
                'query': 'imported eq true'
            })
        self.mock_ansible_module.params = params_get_all_with_filters

        self.testing_class().run()

        self.resource_client.get_all.assert_called_once_with(start=1, count=3, sort='name:descending',
                                                             filter='purpose=General',
                                                             query='imported eq true')

    def test_should_get_all_without_params(self):
        self.__validations()
        self.resource_client.get_all.return_value = []

        params_get_all_with_filters = dict(
            config='config.json',
            name=None
        )
        self.mock_ansible_module.params = params_get_all_with_filters

        self.testing_class().run()

        self.resource_client.get_all.assert_called_once_with()
