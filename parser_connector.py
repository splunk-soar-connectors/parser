# File: parser_connector.py
#
# Copyright (c) 2017-2025 Splunk Inc.
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
import calendar
import dataclasses
import email
import json
import sys
import threading
import time
from typing import Any, NamedTuple, Optional, cast

import phantom.app as phantom
import phantom.rules as ph_rules
from bs4.dammit import UnicodeDammit
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

import parser_const as consts
import parser_email
import parser_methods


@dataclasses.dataclass()
class ParseFileParams:
    remap_cef_fields: str = ""
    is_structured: bool = False
    run_automation: bool = True
    parse_domains: bool = True
    keep_raw: bool = False
    severity: str = "medium"
    artifact_tags: str = ""
    artifact_tags_list: list[str] = dataclasses.field(init=False)
    custom_remap_json: str = "{}"
    custom_mapping: dict[str, Any] = dataclasses.field(init=False)
    custom_mapping_error: Optional[Exception] = None
    text: str = ""

    vault_id: Optional[str] = None
    file_type: Optional[str] = None
    label: Optional[str] = None
    max_artifacts: Optional[int] = None
    container_id: Optional[int] = None

    def __post_init__(self) -> None:
        self.severity = self.severity.lower()
        self.remap_cef_fields = self.remap_cef_fields.lower()
        self.artifact_tags_list = [tag for tag in (_tag.strip().replace(" ", "") for _tag in self.artifact_tags.split(",")) if tag]

        if self.custom_remap_json:
            try:
                self.custom_mapping = json.loads(self.custom_remap_json)
            except Exception as e:
                self.custom_mapping_error = e

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ParseFileParams":
        fields = {field.name for field in dataclasses.fields(cls) if field.init}
        return cls(**{k: v for k, v in d.items() if k in fields})


class SaveContainerResult(NamedTuple):
    success: bool
    container_id: Optional[int]


class FileInfoResult(NamedTuple):
    success: bool
    file_info: Optional[parser_methods.FileInfo]


class HeaderResult(NamedTuple):
    success: bool
    headers: Optional[dict[str, str]]


class EmailVaultData(NamedTuple):
    success: bool
    email_data: Optional[str]
    email_id: Optional[str]


class ParserConnector(BaseConnector):
    def __init__(self) -> None:
        super().__init__()
        self._lock = None
        self._done = False

    def initialize(self) -> bool:
        self._lock = threading.Lock()
        self._done = False

        return phantom.APP_SUCCESS

    def _dump_error_log(self, error: Exception, message: str = "Exception occurred.") -> None:
        self.error_print(message, dump_object=error)

    def _get_error_message_from_exception(self, e: Exception) -> str:
        """This function is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_msg = consts.ERROR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception as e:
            self.error_print(f"Error occurred while fetching exception information. Details: {e!s}")

        if not error_code:
            error_text = f"Error Message: {error_msg}"
        else:
            error_text = f"Error Code: {error_code}. Error Message: {error_msg}"

        return error_text

    def finalize(self) -> bool:
        return phantom.APP_SUCCESS

    def _get_mail_header_dict(self, email_data: str, action_result: ActionResult) -> HeaderResult:
        try:
            mail = email.message_from_string(email_data)
        except Exception as e:
            self._dump_error_log(e)
            return HeaderResult(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Unable to create email object from data. Does not seem to be valid email",
                ),
                None,
            )

        headers = mail.__dict__.get("_headers")

        if not headers:
            return HeaderResult(
                action_result.set_status(
                    phantom.APP_ERROR,
                    "Could not extract header info from email object data. Does not seem to be valid email",
                ),
                None,
            )

        return HeaderResult(phantom.APP_SUCCESS, dict(headers))

    def _get_email_data_from_vault(self, vault_id: str, action_result: ActionResult) -> EmailVaultData:
        email_data = None
        email_id = vault_id

        try:
            _, _, vault_meta_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
            if not vault_meta_info:
                self.debug_print(f"Error while fetching meta information for vault ID: {vault_id}")
                return EmailVaultData(
                    action_result.set_status(phantom.APP_ERROR, consts.PARSER_ERR_FILE_NOT_IN_VAULT),
                    None,
                    None,
                )
            vault_meta_info = list(vault_meta_info)
            file_path = vault_meta_info[0]["path"]
        except Exception as e:
            self._dump_error_log(e)
            return EmailVaultData(
                action_result.set_status(phantom.APP_ERROR, "Could not get file path for vault item"),
                None,
                None,
            )

        if file_path is None:
            return EmailVaultData(
                action_result.set_status(phantom.APP_ERROR, "No file with vault ID found"),
                None,
                None,
            )

        try:
            with open(file_path, "rb") as f:
                email_data = UnicodeDammit(f.read()).unicode_markup
        except Exception as e:
            self._dump_error_log(e)
            error_text = self._get_error_message_from_exception(e)
            return EmailVaultData(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Could not read file contents for vault item. {error_text}",
                ),
                None,
                None,
            )

        return EmailVaultData(phantom.APP_SUCCESS, email_data, email_id)

    def _get_file_info_from_vault(
        self,
        action_result: ActionResult,
        vault_id: str,
        file_type: Optional[str] = None,
    ) -> FileInfoResult:
        file_info = cast(parser_methods.FileInfo, {"id": vault_id})

        # Check for file in vault
        try:
            _, _, vault_meta = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
            if not vault_meta:
                self.debug_print(f"Error while fetching meta information for vault ID: {vault_id}")
                return FileInfoResult(
                    action_result.set_status(phantom.APP_ERROR, consts.PARSER_ERR_FILE_NOT_IN_VAULT),
                    None,
                )
            vault_meta = list(vault_meta)
        except Exception as e:
            self._dump_error_log(e)
            return FileInfoResult(
                action_result.set_status(phantom.APP_ERROR, consts.PARSER_ERR_FILE_NOT_IN_VAULT),
                None,
            )

        file_meta = None
        try:
            for meta in vault_meta:
                if meta.get("container_id") == self.get_container_id():
                    file_meta = meta
                    break
            else:
                self.debug_print(f"Unable to find a file for the vault ID: '{vault_id}' in the container ID: '{self.get_container_id()}'")
        except Exception:
            self.error_print(
                f"Error occurred while finding a file for the vault ID: '{vault_id}' in the container ID: '{self.get_container_id()}'"
            )
            self.debug_print("Considering the first file as the required file")
            file_meta = vault_meta[0]

        if not file_meta:
            self.debug_print(f"Unable to find a file for the vault ID: '{vault_id}' in the container ID: '{self.get_container_id()}'")
            self.debug_print("Considering the first file as the required file")
            file_meta = vault_meta[0]

        file_info["path"] = file_meta["path"]
        file_info["name"] = file_meta["name"]

        # We set the file type to the provided type in the action run
        # instead of keeping it as the default detected file type.
        if file_type:
            file_info["type"] = file_type
        else:
            file_type = cast(str, file_meta["name"].split(".")[-1])
            file_info["type"] = file_type

        return FileInfoResult(phantom.APP_SUCCESS, file_info)

    def _handle_email(
        self,
        action_result: ActionResult,
        vault_id: str,
        label: Optional[str],
        container_id: Optional[int],
        run_automation: bool = True,
        parse_domains: bool = True,
        artifact_tags_list: Optional[list[str]] = None,
    ) -> bool:
        if artifact_tags_list is None:
            artifact_tags_list = []

        ret_val, email_data, email_id = self._get_email_data_from_vault(vault_id, action_result)

        if phantom.is_fail(ret_val) or email_data is None:
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
            "run_automation": run_automation,
            "tags": artifact_tags_list,
        }

        ret_val, response = parser_email.process_email(self, email_data, email_id, config, label, container_id, None)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, response["message"])

        container_id = response["container_id"]

        summary = action_result.update_summary({})
        summary["artifacts_found"] = len(response["artifacts"])
        summary["artifacts_ingested"] = len(response["successful_artifacts"])
        summary["container_id"] = container_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def _save_artifacts(
        self,
        action_result: ActionResult,
        artifacts: list[dict[str, Any]],
        container_id: int,
        severity: str,
        max_artifacts: Optional[int] = None,
        run_automation: bool = True,
        tags: Optional[list[str]] = None,
    ) -> bool:
        if tags is None:
            tags = []
        if max_artifacts:
            artifacts = artifacts[:max_artifacts]

        for artifact in artifacts:
            artifact["container_id"] = container_id
            artifact["severity"] = severity
            artifact["tags"] = tags
            artifact["run_automation"] = run_automation

        if artifacts:
            status, message, id_list = self.save_artifacts(artifacts)
        else:
            return action_result.set_status(phantom.APP_SUCCESS)
        if phantom.is_fail(status):
            message = message + ". Please validate severity parameter"
            return action_result.set_status(phantom.APP_ERROR, message)
        return phantom.APP_SUCCESS

    def _save_to_container(
        self,
        action_result: ActionResult,
        artifacts: list[dict[str, Any]],
        file_name: str,
        label: Optional[str],
        severity: str,
        max_artifacts: Optional[int] = None,
        run_automation: bool = True,
        artifact_tags_list: Optional[list[str]] = None,
    ) -> SaveContainerResult:
        if artifact_tags_list is None:
            artifact_tags_list = []

        container = {
            "name": f"{file_name} Parse Results",
            "label": label,
            "severity": severity,
        }

        status, message, container_id = self.save_container(container)
        if phantom.is_fail(status):
            return SaveContainerResult(action_result.set_status(phantom.APP_ERROR, message), None)
        return SaveContainerResult(
            self._save_artifacts(
                action_result,
                artifacts,
                container_id,
                severity,
                max_artifacts,
                run_automation,
                artifact_tags_list,
            ),
            container_id,
        )

    def _save_to_existing_container(
        self,
        action_result: ActionResult,
        artifacts: list[dict[str, Any]],
        container_id: int,
        severity: str,
        max_artifacts: Optional[int] = None,
        run_automation: bool = True,
        artifact_tags_list: Optional[list[str]] = None,
    ) -> bool:
        return self._save_artifacts(
            action_result,
            artifacts,
            container_id,
            severity,
            max_artifacts,
            run_automation,
            artifact_tags_list,
        )

    def _validate_parse_file_params(self, param: ParseFileParams) -> None:
        try:
            if param.container_id is not None:
                param.container_id = int(param.container_id)
        except Exception as e:
            self._dump_error_log(e)
            raise ValueError("Please provide a valid integer value in container_id") from None

        if param.container_id is None and param.label is None:
            raise ValueError("A label must be specified if no container ID is provided")

        if param.container_id:
            ret_val, message, _ = self.get_container_info(param.container_id)
            if phantom.is_fail(ret_val):
                raise ValueError(f"Unable to find container: {message}")

        # --- remap cef fields ---
        if param.custom_mapping_error is not None:
            self._dump_error_log(param.custom_mapping_error)
            error_text = self._get_error_message_from_exception(param.custom_mapping_error)
            raise ValueError(f"Error: custom_remap_json parameter is not valid json. {error_text}")
        if not isinstance(param.custom_mapping, dict):
            raise ValueError("Error: custom_remap_json parameter is not a dictionary")
        # ---

        if param.vault_id and param.text:
            raise ValueError(
                "Either text can be parsed or a file from the vault can be parsed but both "
                "the 'text' and 'vault_id' parameters cannot be used simultaneously"
            )
        if param.text and param.file_type not in ("txt", "csv", "html"):
            raise ValueError("When using text input, only csv, html, or txt file_type can be used")
        if not (param.vault_id or param.text):
            raise ValueError("Either 'text' or 'vault_id' must be submitted, both cannot be blank")

        if param.max_artifacts is not None:
            try:
                param.max_artifacts = int(param.max_artifacts)
            except Exception as e:
                self._dump_error_log(e)
                raise ValueError("Please provide a valid non-zero positive integer value in max_artifacts") from None
            if param.max_artifacts <= 0:
                raise ValueError("Please provide a valid non-zero positive integer value in max_artifacts")

    def _handle_parse_file(self, action_result: ActionResult, param: ParseFileParams) -> bool:
        try:
            self._validate_parse_file_params(param)
        except ValueError as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        file_info = {}
        if param.vault_id:
            if param.file_type == "email":
                return self._handle_email(
                    action_result,
                    param.vault_id,
                    param.label,
                    param.container_id,
                    param.run_automation,
                    param.parse_domains,
                    param.artifact_tags_list,
                )

            ret_val, file_info = self._get_file_info_from_vault(action_result, param.vault_id, param.file_type)
            if phantom.is_fail(ret_val) or file_info is None:
                return ret_val

            self.debug_print("File Info", file_info)
            if param.is_structured:
                ret_val, response = parser_methods.parse_structured_file(action_result, file_info)
            else:
                ret_val, response = parser_methods.parse_file(self, action_result, file_info, param.parse_domains, param.keep_raw)

            if phantom.is_fail(ret_val):
                return ret_val
        else:
            param.text = param.text.replace(",", ", ")
            ret_val, response = parser_methods.parse_text(self, action_result, param.file_type, param.text, param.parse_domains)
            file_info["name"] = f"Parser_Container_{calendar.timegm(time.gmtime())}"

        if not response:
            return action_result.set_status(
                phantom.APP_ERROR,
                "Unexpected null response; this should not be possible",
            )

        artifacts = response["artifacts"]

        # --- remap cef fields ---
        def _apply_remap(artifacts: list[parser_methods.Artifact], mapping: dict[str, Any]) -> list[parser_methods.Artifact]:
            if not isinstance(artifacts, list) or not isinstance(mapping, dict):
                return artifacts
            if len(artifacts) == 0 or len(mapping) == 0:
                return artifacts
            for a in artifacts:
                new_cef = dict()
                for k, v in list(a["cef"].items()):
                    if k in mapping:
                        new_cef[mapping[k]] = v
                    else:
                        new_cef[k] = v
                a["cef"] = new_cef
            return artifacts

        if "do not" in param.remap_cef_fields:
            # --- do not perform CEF -> CIM remapping
            artifacts = _apply_remap(artifacts, param.custom_mapping)
        elif "before" in param.remap_cef_fields:
            # --- apply CEF -> CIM remapping and then custom remapping
            artifacts = _apply_remap(artifacts, consts.CEF2CIM_MAPPING)
            artifacts = _apply_remap(artifacts, param.custom_mapping)
        elif "after" in param.remap_cef_fields:
            # --- apply custom remapping and then CEF -> CIM remapping
            artifacts = _apply_remap(artifacts, param.custom_mapping)
            artifacts = _apply_remap(artifacts, consts.CEF2CIM_MAPPING)
        # ---

        if not param.container_id:
            ret_val, container_id = self._save_to_container(
                action_result,
                cast(list[dict[str, Any]], artifacts),
                file_info["name"],
                param.label,
                param.severity,
                param.max_artifacts,
                param.run_automation,
                param.artifact_tags_list,
            )
            if phantom.is_fail(ret_val):
                return ret_val
        else:
            container_id = param.container_id
            ret_val = self._save_to_existing_container(
                action_result,
                cast(list[dict[str, Any]], artifacts),
                container_id,
                param.severity,
                param.max_artifacts,
                param.run_automation,
                param.artifact_tags_list,
            )
            if phantom.is_fail(ret_val):
                return ret_val

        if param.max_artifacts:
            len_artifacts = len(artifacts[: param.max_artifacts])
        else:
            len_artifacts = len(artifacts)

        summary = action_result.update_summary({})
        summary["artifacts_found"] = len(response["artifacts"])
        summary["artifacts_ingested"] = len_artifacts
        summary["container_id"] = container_id

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param: dict[str, Any]) -> bool:
        ret_val = phantom.APP_SUCCESS

        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        action_result = self.add_action_result(ActionResult(dict(param)))
        if action_id == "parse_file":
            ret_val = self._handle_parse_file(action_result, ParseFileParams.from_dict(param))

        return ret_val


if __name__ == "__main__":
    import argparse

    import pudb
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None

    verify = args.verify

    if args.username and args.password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=consts.DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]
            data = {
                "username": args.username,
                "password": args.password,
                "csrfmiddlewaretoken": csrftoken,
            }
            headers = {
                "Cookie": f"csrftoken={csrftoken}",
                "Referer": login_url,
            }

            print("Logging into Platform to get the session id")
            r2 = requests.post(
                login_url,
                verify=verify,
                data=data,
                headers=headers,
                timeout=consts.DEFAULT_REQUEST_TIMEOUT,
            )
            session_id = r2.cookies["sessionid"]

        except Exception as e:
            print(f"Unable to get session id from the platform. Error: {e!s}")
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ParserConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
