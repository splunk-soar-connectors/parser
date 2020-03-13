# File: parser_connector.py
# Copyright (c) 2017-2020 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
from phantom.vault import Vault

import json
import email
import threading
import parser_email
import parser_methods
import time
import calendar

from parser_const import *


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
            return RetVal2(action_result.set_status(phantom.APP_ERROR,
                                        "Unable to create email object from data. Does not seem to be valid email"),
                                        None)

        headers = mail.__dict__.get('_headers')

        if not headers:
            return RetVal2(action_result.set_status(phantom.APP_ERROR,
                        "Could not extract header info from email object data. Does not seem to be valid email"),
                         None)

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
        except Exception:
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                                                "Could not get file path for vault item"),
                                                None,
                                                None)

        if file_path is None:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, "No file with vault ID found"), None, None)

        try:
            with open(file_path, 'r') as f:
                email_data = f.read()
        except Exception as e:
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                                                "Could not read file contents for vault item", e), None, None)

        return RetVal3(phantom.APP_SUCCESS, email_data, email_id)

    def _get_file_info_from_vault(self, action_result, vault_id, file_type=None):
        file_info = {}
        file_info['id'] = vault_id

        try:
            info = Vault.get_file_info(vault_id=vault_id)[0]
        except IndexError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No file with vault ID found"), None)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR,
                                                "Error retrieving file from vault: {0}".format(str(e))), None)
        file_info['path'] = info['path']
        file_info['name'] = info['name']
        if file_type:
            file_info['type'] = file_type
        else:
            file_type = info['name'].split('.')[-1]
            file_info['type'] = file_type

        return RetVal(phantom.APP_SUCCESS, file_info)

    def _handle_email(self, action_result, vault_id, label, container_id, run_automation=True):
        ret_val, email_data, email_id = self._get_email_data_from_vault(vault_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, header_dict = self._get_mail_header_dict(email_data, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(header_dict)

        config = {
            "extract_attachments": True,
            "extract_domains": True,
            "extract_hashes": True,
            "extract_ips": True,
            "extract_urls": True,
            "run_automation": run_automation
        }

        ret_val, response = parser_email.process_email(self, email_data, email_id, config, label, container_id, None)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, response['message'])

        container_id = response['container_id']

        action_result.update_summary({"container_id": container_id})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_artifacts(self, action_result, artifacts, container_id, severity, max_artifacts=None, run_automation=True):
        if max_artifacts:
            artifacts = artifacts[:max_artifacts]

        for artifact in artifacts:
            artifact['container_id'] = container_id
            artifact['severity'] = severity
            if not run_automation:
                artifact['run_automation'] = False

        if artifacts:
            status, message, id_list = self.save_artifacts(artifacts)
        else:
            return action_result.set_status(phantom.APP_SUCCESS)
        if phantom.is_fail(status):
            message = message + '. Please validate severity parameter'
            return action_result.set_status(phantom.APP_ERROR, message)
        return phantom.APP_SUCCESS

    def _save_to_container(self, action_result, artifacts, file_name, label, severity, max_artifacts=None, run_automation=True):
        container = {}
        container['name'] = "{0} Parse Results".format(file_name)
        container['label'] = label
        container['severity'] = severity

        status, message, container_id = self.save_container(container)
        if phantom.is_fail(status):
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        return RetVal(self._save_artifacts(action_result,
                                        artifacts, container_id, severity, max_artifacts, run_automation), container_id)

    def _save_to_existing_container(self, action_result, artifacts,
                                    container_id, severity, max_artifacts=None, run_automation=True):
        return self._save_artifacts(action_result, artifacts, container_id, severity, max_artifacts, run_automation)

    def _handle_parse_file(self, param):  # noqa
        action_result = self.add_action_result(ActionResult(dict(param)))
        container_id = param.get('container_id')
        label = param.get('label')
        file_info = {}
        if container_id is None and label is None:
            return action_result.set_status(phantom.APP_ERROR,
                                            "A label must be specified if no container ID is provided")
        if container_id:
            ret_val, message, _ = self.get_container_info(container_id)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, "Unable to find container: {}".format(message))

        vault_id = param.get('vault_id')
        text_val = param.get('text')
        file_type = param.get('file_type')
        is_structured = param.get('is_structured')
        run_automation = param.get('run_automation', True)
        severity = param.get('severity', 'medium').lower()

        # --- remap cef fields ---
        custom_remap_json = param.get("custom_remap_json", "{}")
        custom_mapping = None
        if custom_remap_json:
            try:
                custom_mapping = json.loads(custom_remap_json)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Error: custom_remap_json parameter is not valid json; {}".format(e))
        if not isinstance(custom_mapping, dict):
            return action_result.set_status(phantom.APP_ERROR, "Error: custom_remap_json parameter is not a dictionary")
        # ---

        if vault_id and text_val:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Either text can be parsed or a file from the vault can be parsed but both the 'text' and 'vault_id' parameters cannot be used simultaneously"
            )
        if text_val and file_type not in ['txt', 'csv', 'html']:
            return action_result.set_status(phantom.APP_ERROR,
                                        "When using text input, only csv, html, or txt file_type can be used")
        elif not(vault_id or text_val):
            return action_result.set_status(phantom.APP_ERROR,
                                        "Either 'text' or 'vault_id' must be submitted, both cannot be blank")

        if vault_id:
            if file_type == 'email':
                return self._handle_email(action_result, vault_id, label, container_id, run_automation)

            ret_val, file_info = self._get_file_info_from_vault(action_result, vault_id, file_type)
            if phantom.is_fail(ret_val):
                return ret_val

            self.debug_print("File Info", file_info)
            if is_structured:
                ret_val, response = parser_methods.parse_structured_file(self, action_result, file_info)
            else:
                ret_val, response = parser_methods.parse_file(self, action_result, file_info)
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            ret_val, response = parser_methods.parse_text(self, action_result, file_type, text_val)
            file_info['name'] = 'Parser_Container_{0}'.format(calendar.timegm(time.gmtime()))

        artifacts = response['artifacts']

        # --- remap cef fields ---
        def _apply_remap(artifacts, mapping):
            if not isinstance(artifacts, list) or not isinstance(mapping, dict):
                return artifacts
            if len(artifacts) == 0 or len(mapping) == 0:
                return artifacts
            for a in artifacts:
                newcef = dict()
                for k, v in list(a['cef'].items()):
                    if k in mapping:
                        newcef[mapping[k]] = v
                    else:
                        newcef[k] = v
                a['cef'] = newcef
            return artifacts

        remap_cef_fields = param.get("remap_cef_fields", "").lower()
        if "do not" in remap_cef_fields:
            # --- do not perform CEF -> CIM remapping
            artifacts = _apply_remap(artifacts, custom_mapping)
        elif "before" in remap_cef_fields:
            # --- apply CEF -> CIM remapping and then custom remapping
            artifacts = _apply_remap(artifacts, CEF2CIM_MAPPING)
            artifacts = _apply_remap(artifacts, custom_mapping)
        elif "after" in remap_cef_fields:
            # --- apply custom remapping and then CEF -> CIM remapping
            artifacts = _apply_remap(artifacts, custom_mapping)
            artifacts = _apply_remap(artifacts, CEF2CIM_MAPPING)
        # ---

        max_artifacts = param.get('max_artifacts')
        if max_artifacts is not None:
            try:
                max_artifacts = int(max_artifacts)
            except ValueError:
                return action_result.set_status(phantom.APP_ERROR, "max_artifacts must be an integer")
        if (max_artifacts and not str(max_artifacts).isdigit()) or max_artifacts == 0:
            return action_result.set_status(phantom.APP_ERROR, "max_artifacts must be greater than 0")

        if not container_id:
            ret_val, container_id = self._save_to_container(action_result,
                                                        artifacts,
                                                        file_info['name'],
                                                        label, severity,
                                                        max_artifacts, run_automation)
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            ret_val = self._save_to_existing_container(action_result,
                                                    artifacts, container_id, severity, max_artifacts, run_automation)
            if phantom.is_fail(ret_val):
                return ret_val

        summary = action_result.update_summary({})
        summary['artifacts_found'] = len(response['artifacts'])
        summary['container_id'] = container_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'parse_file':
            ret_val = self._handle_parse_file(param)

        return ret_val


if __name__ == '__main__':

    import sys
    import pudb
    import argparse
    import requests
    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    if (args.username and args.password):
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']
            data = {'username': args.username, 'password': args.password, 'csrfmiddlewaretoken': csrftoken}
            headers = {'Cookie': 'csrftoken={0}'.format(csrftoken), 'Referer': login_url}

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']

        except Exception as e:
            print(("Unable to get session id from the platform. Error: {0}".format(str(e))))
            exit(1)

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ParserConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
