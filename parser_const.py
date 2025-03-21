# File: parser_const.py
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
_CEF2CIM_override = {
    "fileHash": "file_hash",
    "sourceAddress": "src_ip",
    "sourceDnsDomain": "src_dns",
    "destinationAddress": "dest_ip",
    "destinationDnsDomain": "dest_dns",
}

_TAcef_template = {
    # TA-cef_template https://splunkbase.splunk.com/app/3705
    "act": "vendor_action",
    "deviceAction": "vendor_action",
    "cat": "category",
    "deviceEventCategory": "category",
    "dhost": "dest_host",
    "destinationHostName": "dest_host",
    "dpid": "dest_pid",
    "destinationProcessId": "dest_pid",
    "dmac": "dest_mac",
    "destinationMacAddress": "dest_mac",
    "dntdom": "dest_nt_domain",
    "destinationNtDomain": "dest_nt_domain",
    "dproc": "dest_process",
    "destinationProcessName": "dest_process",
    "dpt": "dest_port",
    "destinationPort": "dest_port",
    "dst": "dest",
    "destinationAddress": "dest",
    "duid": "dest_user_id",
    "destinationUserId": "dest_user_id",
    "duser": "dest_user",
    "destinationUserName": "dest_user",
    "dvchost": "dvc_host",
    "deviceHostName": "dvc_host",
    "dvcpid": "dvc_pid",
    "deviceProcessId": "dvc_pid",
    "fname": "file_name",
    "fileName": "file_name",
    "fsize": "file_size",
    "fileSize": "file_size",
    "in": "bytes_in",
    "bytesIn": "bytes_in",
    "msg": "message",
    "message": "message",
    "outcome": "vendor_outcome",
    "eventOutcome": "vendor_outcome",
    "out": "bytes_out",
    "bytesOut": "bytes_out",
    "proto": "protocol",
    "transportProtocol": "protocol",
    "request": "url",
    "requestURL": "url",
    "shost": "src_host",
    "sourceHostName": "src_host",
    "smac": "src_mac",
    "sourceMacAddress": "src_mac",
    "sntdom": "src_nt_domain",
    "sourceNtDomain": "src_nt_domain",
    "spid": "src_pid",
    "sourceProcessId": "src_pid",
    "sproc": "src_process",
    "sourceProcessName": "src_process",
    "spt": "src_port",
    "sourcePort": "src_port",
    "suid": "src_user_id",
    "sourceUserId": "src_user_id",
    "suser": "src_user",
    "sourceUserName": "src_user",
}

_splunk_app_cef = {
    # splunk_app_cef https://splunkbase.splunk.com/app/1847/
    "syslog_time": "_time",
    "Syslog Time": "_time",
    "syslog_host": "host",
    "Syslog Host": "host",
    "dvc_product": "vendor_product",
    "Device Product": "vendor_product",
    "dvc_version": "product_version",
    "Device Version": "product_version",
    "signature_id": "signature_id",
    "Signature ID": "signature_id",
    "name": "signature",
    "Name": "signature",
    "act": "action",
    "deviceAction": "action",
    "app": "app",
    "ApplicationProtocol": "app",
    "cat": "category",
    "deviceEventCategory": "category",
    "destinationDnsDomain": "dest_dns",
    "destinationServiceName": "service",
    "dntdom": "dest_nt_domain",
    "destinationNtDomain": "dest_nt_domain",
    "dpid": "process_id",
    "destinationProcessId": "process_id",
    "dproc": "process",
    "destinationProcessName": "process",
    "dpt": "dest_port",
    "destinationPort": "dest_port",
    "dst": "dest",
    "destinationAddress": "dest",
    "duid": "user_id",
    "destinationUserId": "user_id",
    "duser": "user",
    "destinationUserName": "user",
    "dvc": "dvc",
    "deviceAddress": "dvc",
    "fileHash": "file_hash",
    "filePath": "file_path",
    "fname": "file_name",
    "fileName": "file_name",
    "fsize": "file_size",
    "fileSize": "file_size",
    "in": "bytes_in",
    "bytesIn": "bytes_in",
    "out": "bytes_out",
    "bytesOut": "bytes_out",
    "proto": "transport",
    "transportProtocol": "transport",
    "request": "url",
    "requestURL": "url",
    "requestMethod": "http_method",
    "rt": "_indextime",
    "receiptTime": "_indextime",
    "sntdom": "src_nt_domain",
    "sourceNtDomain": "src_nt_domain",
    "spt": "src_port",
    "sourcePort": "src_port",
    "src": "src",
    "SourceAddress": "src",
    "suid": "src_user_id",
    "sourceUserId": "src_user_id",
    "suser": "src_user",
    "sourceUserName": "src_user",
    "dlat": "dest_lat",
    "destinationGeoLatitude": "dest_lat",
    "dlong": "dest_long",
    "destinationGeoLongitude": "dest_long",
    "eventId": "event_id",
    "rawEvent": "_raw",
    "slat": "src_lat",
    "sourceGeoLatitude": "src_lat",
    "slong": "src_long",
    "sourceGeoLongitude": "src_long",
}

CEF2CIM_MAPPING = dict()
CEF2CIM_MAPPING.update(_TAcef_template)
CEF2CIM_MAPPING.update(_splunk_app_cef)
CEF2CIM_MAPPING.update(_CEF2CIM_override)

PARSER_ERR_FILE_NOT_IN_VAULT = "Could not find specified vault ID in vault"

DEFAULT_REQUEST_TIMEOUT = 30  # in seconds

# Constants relating to '_get_error_message_from_exception'
ERROR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
