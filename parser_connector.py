# --
# File: parser_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --
# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

# Usage of the consts file is recommended
# from parser_consts import *
import json
import email
import threading
import parser_email
import parser_methods


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class RetVal2(RetVal):
    pass


class RetVal3(tuple):
    def __new__(cls, val1, val2, val3):
        return tuple.__new__(RetVal3, (val1, val2, val3))


class ParserConnector(BaseConnector):

    def __init__(self):
        super(ParserConnector, self).__init__()

    def initialize(self):
        self._lock = threading.Lock()
        self._done = False
        return phantom.APP_SUCCESS

    def finalize(self):
        return phantom.APP_SUCCESS

    def _get_mail_header_dict(self, email_data, action_result):
        try:
            mail = email.message_from_string(email_data)
        except:
            return RetVal2(action_result.set_status(phantom.APP_ERROR, "Unable to create email object from data. Does not seem to be valid email"), None)

        headers = mail.__dict__.get('_headers')

        if (not headers):
            return RetVal2(action_result.set_status(phantom.APP_ERROR, "Could not extract header info from email object data. Does not seem to be valid email"), None)

        ret_val = {}
        for header in headers:
            ret_val[header[0]] = header[1]

        return RetVal2(phantom.APP_SUCCESS, ret_val)

    def _get_email_data_from_vault(self, vault_id, action_result):

        email_data = None
        email_id = vault_id
        file_path = None

        try:
            file_path = Vault.get_file_path(vault_id)
        except Exception as e:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, "Could not get file path for vault item"), None, None)

        try:
            with open(file_path, 'r') as f:
                email_data = f.read()
        except Exception as e:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, "Could not read file contents for vault item", e), None, None)

        return RetVal3(phantom.APP_SUCCESS, email_data, email_id)

    def _get_file_info_from_vault(self, action_result, vault_id, file_type=None):
        file_info = {}
        file_info['id'] = vault_id
        try:
            info = Vault.get_file_info(vault_id=vault_id)[0]
        except IndexError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No file with vault ID found"), None)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error retrieving file from vault: {0}".format(str(e))), None)
        file_info['path'] = info['path']
        file_info['name'] = info['name']
        if file_type:
            file_info['type'] = file_type
        else:
            file_type = info['name'].split('.')[-1]
            file_info['type'] = file_type

        return RetVal(phantom.APP_SUCCESS, file_info)

    def _handle_email(self, action_result, vault_id, label, container_id):
        ret_val, email_data, email_id = self._get_email_data_from_vault(vault_id, action_result)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        ret_val, header_dict = self._get_mail_header_dict(email_data, action_result)
        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(header_dict)

        config = {
                "extract_attachments": True,
                "extract_domains": True,
                "extract_hashes": True,
                "extract_ips": True,
                "extract_urls": True }

        ret_val, response = parser_email.process_email(self, email_data, email_id, config, label, container_id, None)

        if (phantom.is_fail(ret_val)):
            return action_result.set_status(phantom.APP_ERROR, response['message'])

        container_id = response['container_id']

        action_result.update_summary({"container_id": container_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_artifacts(self, action_result, artifacts, container_id, max_artifacts=None):
        if max_artifacts:
            artifacts = artifacts[:max_artifacts]

        for artifact in artifacts:
            artifact['container_id'] = container_id
        if artifacts:
            status, message, id_list = self.save_artifacts(artifacts)
        else:
            # No IOCS found
            return action_result.set_status(phantom.APP_SUCCESS)
        if phantom.is_fail(status):
            return action_result.set_status(phantom.APP_ERROR, message)
        return phantom.APP_SUCCESS

    def _save_to_container(self, action_result, artifacts, file_name, label, max_artifacts=None):
        container = {}
        container['name'] = "{0} Parse Results".format(file_name)
        container['label'] = label

        status, message, container_id = self.save_container(container)
        if phantom.is_fail(status):
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        return RetVal(self._save_artifacts(action_result, artifacts, container_id, max_artifacts), container_id)

    def _save_to_existing_container(self, action_result, artifacts, container_id, max_artifacts=None):
        return self._save_artifacts(action_result, artifacts, container_id, max_artifacts)

    def _handle_parse_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_id = param.get('container_id')
        label = param.get('label')
        if container_id is None and label is None:
            return action_result.set_status(phantom.APP_ERROR, "A label must be specified if no container ID is provided")
        vault_id = param['vault_id']
        file_type = param.get('file_type')

        if (file_type == 'email'):
            # Emails are handled differently
            return self._handle_email(action_result, vault_id, label, container_id)

        ret_val, file_info = self._get_file_info_from_vault(action_result, vault_id, file_type)
        if phantom.is_fail(ret_val):
            return ret_val

        self.debug_print("File Info", file_info)
        ret_val, response = parser_methods.parse_file(self, action_result, file_info)
        if phantom.is_fail(ret_val):
            return ret_val

        artifacts = response['artifacts']
        max_artifacts = param.get('max_artifacts')
        if max_artifacts:
            try:
                max_artifacts = int(max_artifacts)
            except TypeError:
                return action_result.set_status(phantom.APP_ERROR, "max_artifacts must be an integer")
            if max_artifacts < 1:
                return action_result.set_status(phantom.APP_ERROR, "max_artifacts must be greater than 0")

        if not container_id:
            ret_val, container_id = self._save_to_container(action_result, artifacts, file_info['name'], label, max_artifacts)
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            ret_val = self._save_to_existing_container(action_result, artifacts, container_id, max_artifacts)
            if phantom.is_fail(ret_val):
                return ret_val

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['artifacts_found'] = len(response['artifacts'])
        summary['container_id'] = container_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'parse_file':
            ret_val = self._handle_parse_file(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ParserConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)