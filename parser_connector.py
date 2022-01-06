# File: parser_connector.py
#
# Copyright (c) 2017-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom App imports
import calendar
import email
import json
import sys
import threading
import time

import phantom.app as phantom
import phantom.rules as ph_rules
from bs4 import UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import parser_email
import parser_methods
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
        self._lock = None
        self._done = False
        self._python_version = int(sys.version_info[0])

    def initialize(self):
        self._lock = threading.Lock()
        self._done = False

        try:
            self._python_version = int(sys.version_info[0])
        except Exception:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        return phantom.APP_SUCCESS

    def _get_error_message_from_exception(self, e):
        """ This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_msg = "Unknown error occurred. Please check the asset configuration and|or action parameters."
        error_code = "Error code unavailable"
        error = "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)
        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_code = "Error code unavailable"
                    error_msg = e.args[0]
            else:
                error_code = error_code
                error_msg = error_msg
        except Exception:
            return error

        return "Error Code: {0}. Error Message: {1}".format(error_code, error_msg)

    def finalize(self):
        return phantom.APP_SUCCESS

    def _get_mail_header_dict(self, email_data, action_result):
        try:
            mail = email.message_from_string(email_data)
        except Exception:
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

        try:
            _, _, vault_meta_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
            if not vault_meta_info:
                self.debug_print("Error while fetching meta information for vault ID: {}".format(vault_id))
                return RetVal3(action_result.set_status(phantom.APP_ERROR, PARSER_ERR_FILE_NOT_IN_VAULT), None, None)
            vault_meta_info = list(vault_meta_info)
            file_path = vault_meta_info[0]['path']
        except Exception:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, "Could not get file path for vault item"), None,
                           None)

        if file_path is None:
            return RetVal3(action_result.set_status(phantom.APP_ERROR, "No file with vault ID found"), None, None)

        try:
            if self._python_version >= 3:
                with open(file_path, 'rb') as f:
                    email_data = UnicodeDammit(f.read()).unicode_markup
            elif self._python_version < 3:
                with open(file_path, 'r') as f:
                    email_data = f.read()
        except Exception as e:
            error_text = self._get_error_message_from_exception(e)
            return RetVal3(action_result.set_status(phantom.APP_ERROR,
                                                    "Could not read file contents for vault item. {}".format(error_text)),
                           None, None)

        return RetVal3(phantom.APP_SUCCESS, email_data, email_id)

    def _get_file_info_from_vault(self, action_result, vault_id, file_type=None):
        file_info = {'id': vault_id}

        # Check for file in vault
        try:
            _, _, vault_meta = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
            if not vault_meta:
                self.debug_print("Error while fetching meta information for vault ID: {}".format(vault_id))
                return RetVal(action_result.set_status(phantom.APP_ERROR, PARSER_ERR_FILE_NOT_IN_VAULT), None)
            vault_meta = list(vault_meta)
        except Exception:
            return RetVal(action_result.set_status(phantom.APP_ERROR, PARSER_ERR_FILE_NOT_IN_VAULT), None)

        file_meta = None
        try:
            for meta in vault_meta:
                if meta.get("container_id") == self.get_container_id():
                    file_meta = meta
                    break
            else:
                self.debug_print(
                    "Unable to find a file for the vault ID: "
                    "'{0}' in the container ID: '{1}'".format(vault_id, self.get_container_id()))
        except Exception:
            self.debug_print(
                "Error occurred while finding a file for the vault ID: "
                "'{0}' in the container ID: '{1}'".format(vault_id, self.get_container_id()))
            self.debug_print("Considering the first file as the required file")
            file_meta = vault_meta[0]

        if not file_meta:
            self.debug_print(
                "Unable to find a file for the vault ID: "
                "'{0}' in the container ID: '{1}'".format(vault_id, self.get_container_id()))
            self.debug_print("Considering the first file as the required file")
            file_meta = vault_meta[0]

        file_info['path'] = file_meta['path']
        file_info['name'] = file_meta['name']

        # We set the file type to the provided type in the action run
        # instead of keeping it as the default detected file type.
        if file_type:
            file_info['type'] = file_type
        else:
            file_type = file_meta['name'].split('.')[-1]
            file_info['type'] = file_type

        return RetVal(phantom.APP_SUCCESS, file_info)

    def _handle_email(self, action_result, vault_id, label, container_id, run_automation=True, parse_domains=True):
        ret_val, email_data, email_id = self._get_email_data_from_vault(vault_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, header_dict = self._get_mail_header_dict(email_data, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(header_dict)

        config = {
            "extract_attachments": True,
            "extract_domains": parse_domains,
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

    def _save_artifacts(self, action_result, artifacts, container_id, severity, max_artifacts=None, run_automation=True, tags=[]):
        if max_artifacts:
            artifacts = artifacts[:max_artifacts]

        for artifact in artifacts:
            artifact['container_id'] = container_id
            artifact['severity'] = severity
            artifact['tags'] = tags
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

    def _save_to_container(self, action_result, artifacts, file_name, label,
                           severity, max_artifacts=None, run_automation=True, artifact_tags_list=[]):
        container = {'name': "{0} Parse Results".format(file_name), 'label': label, 'severity': severity}

        status, message, container_id = self.save_container(container)
        if phantom.is_fail(status):
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)
        return RetVal(
            self._save_artifacts(
                action_result, artifacts, container_id, severity, max_artifacts, run_automation, artifact_tags_list),
            container_id)

    def _save_to_existing_container(self, action_result, artifacts, container_id,
                                    severity, max_artifacts=None, run_automation=True, artifact_tags_list=[]):
        return self._save_artifacts(action_result, artifacts, container_id, severity, max_artifacts, run_automation,
                                    artifact_tags_list)

    def get_artifact_tags_list(self, artifact_tags):
        """
        Get list of tags from comma separated tags string
        Args:
            artifact_tags: Comma separated string of tags

        Returns:
            list: tags
        """
        tags = artifact_tags.split(",")
        tags = [tag.strip().replace(" ", "") for tag in tags]
        return list(filter(None, tags))

    def _handle_parse_file(self, param):  # noqa

        action_result = self.add_action_result(ActionResult(dict(param)))

        container_id = param.get('container_id')
        try:
            if container_id is not None:
                container_id = int(container_id)
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Please provide a valid integer value in container_id")

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
        is_structured = param.get('is_structured', False)
        run_automation = param.get('run_automation', True)
        parse_domains = param.get('parse_domains', True)
        keep_raw = param.get('keep_raw', False)
        severity = param.get('severity', 'medium').lower()
        artifact_tags = param.get('artifact_tags', "")

        artifact_tags_list = self.get_artifact_tags_list(artifact_tags)

        # --- remap cef fields ---
        custom_remap_json = param.get("custom_remap_json", "{}")
        custom_mapping = None
        if custom_remap_json:
            try:
                custom_mapping = json.loads(custom_remap_json)
            except Exception as e:
                error_text = self._get_error_message_from_exception(e)
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Error: custom_remap_json parameter is not valid json. {}".format(error_text))
        if not isinstance(custom_mapping, dict):
            return action_result.set_status(phantom.APP_ERROR, "Error: custom_remap_json parameter is not a dictionary")
        # ---

        if vault_id and text_val:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Either text can be parsed or "
                "a file from the vault can be parsed but both the 'text' and "
                "'vault_id' parameters cannot be used simultaneously"
            )
        if text_val and file_type not in ['txt', 'csv', 'html']:
            return action_result.set_status(
                phantom.APP_ERROR, "When using text input, only csv, html, or txt file_type can be used")
        elif not(vault_id or text_val):
            return action_result.set_status(
                phantom.APP_ERROR, "Either 'text' or 'vault_id' must be submitted, both cannot be blank")

        if vault_id:
            if file_type == 'email':
                return self._handle_email(action_result, vault_id, label, container_id, run_automation, parse_domains)

            ret_val, file_info = self._get_file_info_from_vault(action_result, vault_id, file_type)
            if phantom.is_fail(ret_val):
                return ret_val

            self.debug_print("File Info", file_info)
            if is_structured:
                ret_val, response = parser_methods.parse_structured_file(action_result, file_info)
            else:
                ret_val, response = parser_methods.parse_file(self, action_result, file_info, parse_domains, keep_raw)

            if phantom.is_fail(ret_val):
                return ret_val
        else:
            text_val = text_val.replace(",", ", ")
            ret_val, response = parser_methods.parse_text(self, action_result, file_type, text_val, parse_domains)
            file_info['name'] = 'Parser_Container_{0}'.format(calendar.timegm(time.gmtime()))

        artifacts = response['artifacts']

        # --- remap cef fields ---
        def _apply_remap(artifacts, mapping):
            if not isinstance(artifacts, list) or not isinstance(mapping, dict):
                return artifacts
            if len(artifacts) == 0 or len(mapping) == 0:
                return artifacts
            for a in artifacts:
                new_cef = dict()
                for k, v in list(a['cef'].items()):
                    if k in mapping:
                        new_cef[mapping[k]] = v
                    else:
                        new_cef[k] = v
                a['cef'] = new_cef
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
                if max_artifacts <= 0:
                    return action_result.set_status(
                        phantom.APP_ERROR, "Please provide a valid non-zero positive integer value in max_artifacts")
            except Exception:
                return action_result.set_status(
                    phantom.APP_ERROR, "Please provide a valid non-zero positive integer value in max_artifacts")

        if not container_id:
            ret_val, container_id = self._save_to_container(
                action_result, artifacts, file_info['name'],
                label, severity, max_artifacts, run_automation, artifact_tags_list)
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            ret_val = self._save_to_existing_container(
                action_result, artifacts, container_id, severity, max_artifacts, run_automation, artifact_tags_list)
            if phantom.is_fail(ret_val):
                return ret_val

        if max_artifacts:
            len_artifacts = len(artifacts[:max_artifacts])
        else:
            len_artifacts = len(artifacts)

        summary = action_result.update_summary({})
        summary['artifacts_found'] = len(response['artifacts'])
        summary['artifacts_ingested'] = len_artifacts
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

    import argparse

    import pudb
    import requests
    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    if args.username and args.password:
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

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ParserConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
