# --
# File: parse_methods.py
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

import re
import csv
import socket
import zipfile
from lxml import etree
from bs4 import BeautifulSoup
from cStringIO import StringIO

import phantom.app as phantom
import phantom.utils as ph_utils

from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import TextConverter
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter

import time
import threading


_container_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

_artifact_common = {
    "run_automation": False  # Don't run any playbooks, when this artifact is added
}

URI_REGEX = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
EMAIL_REGEX = r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
EMAIL_REGEX2 = r'".*"@[A-Z0-9.-]+\.[A-Z]{2,}\b'
HASH_REGEX = r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b"
IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
IPV6_REGEX = r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))'
IPV6_REGEX += r'|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|'
IPV6_REGEX += r'(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*'


def _extract_domain_from_url(url):
    domain = phantom.get_host_from_url(url)
    if domain and not _is_ip(domain):
        return domain
    return None


def _is_ip(input_ip):
    if (ph_utils.is_ip(input_ip)):
        return True

    if (is_ipv6(input_ip)):
        return True

    return False


def _clean_url(url):
    url = url.strip('>),.]\r\n')

    # Check before splicing, find returns -1 if not found
    # _and_ you will end up splicing on -1 (incorrectly)
    if ('<' in url):
        url = url[:url.find('<')]

    if ('>' in url):
        url = url[:url.find('>')]

    return url


def is_ipv6(input_ip):
    try:
        socket.inet_pton(socket.AF_INET6, input_ip)
    except:  # not a valid v6 address
        return False

    return True


class TextIOCParser():
    BASE_PATTERNS = [
        {
            'cef': 'ip',             # Name of CEF field
            'pattern': IP_REGEX,     # Regex to match
            'name': 'IP Artifact',   # Name of artifact
            'validator': _is_ip      # Additional function to verify matched string (Should return true or false)
        },
        {
            'cef': 'ip',
            'pattern': IPV6_REGEX,
            'name': 'IP Artifact',
            'validator': _is_ip
        },
        {
            'cef': 'requestURL',
            'pattern': URI_REGEX,
            'name': 'URL Artifact',
            'clean': _clean_url,     # Additional cleaning of data from regex (Should return a string)
            'subtypes': [            # Additional IOCs to find in a matched one
                # If you really wanted to, you could also have subtypes in the subtypes
                {
                    'cef': 'domain',
                    'name': 'Domain Artifact',
                    'callback': _extract_domain_from_url   # Method to extract substring
                }
            ]
            # We dont need to worry about the case where an IP is the 'main' part of the url, since the two
            # IP regexes are already going to find those
        },
        {
            'cef': 'fileHash',
            'pattern': HASH_REGEX,
            'name': 'Hash Artifact'
        },
        {
            'cef': 'email',
            'pattern': EMAIL_REGEX,
            'name': 'Email Artifact',
            'subtypes': [
                {
                    'cef': 'domain',
                    'name': 'Domain Artifact',
                    'callback': lambda(x): x[x.rfind('@') + 1:],
                    'validator': lambda(x): not _is_ip(x)
                }
            ]
        },
        {
            'cef': 'email',
            'pattern': EMAIL_REGEX2,
            'name': 'Email Artifact',
            'subtypes': [
                {
                    'cef': 'domain',
                    'name': 'Domain Artifact',
                    'callback': lambda(x): x[x.rfind('@') + 1:],
                    'validator': lambda(x): not _is_ip(x)
                }
            ]
        }
    ]
    found_values = set()

    def __init__(self, patterns=None):
        self.patterns = self.BASE_PATTERNS if patterns is None else patterns
        self.added_artifacts = 0

    def _create_artifact(self, artifacts, value, cef, name):
        artifact = {}
        artifact.update(_artifact_common)
        artifact['source_data_identifier'] = self.added_artifacts
        artifact['cef'] = {cef: value}
        artifact['name'] = name
        artifacts.append(artifact)
        self.added_artifacts += 1
        self.found_values.add(value)

    def _parse_ioc_subtype(self, artifacts, value, subtype):
        callback = subtype.get('callback')
        if callback:
            sub_val = callback(value)
            self._pass_over_value(artifacts, sub_val, subtype)

    def _pass_over_value(self, artifacts, value, ioc):
        validator = ioc.get('validator')
        clean = ioc.get('clean')
        subtypes = ioc.get('subtypes', [])
        if not value:
            return
        if value in self.found_values:
            return
        if clean:
            value = clean(value)
        if validator and not validator(value):
            return
        self._create_artifact(artifacts, value, ioc['cef'], ioc['name'])
        for st in subtypes:
            self._parse_ioc_subtype(artifacts, value, st)

    def parse_to_artifacts(self, text):
        artifacts = []
        for ioc in self.patterns:
            regexp = re.compile(ioc['pattern'], re.IGNORECASE)
            found = regexp.findall(text)
            for match in found:
                if type(match) == tuple:
                    for x in match:
                        self._pass_over_value(artifacts, x, ioc)
                else:
                    self._pass_over_value(artifacts, match, ioc)
        return artifacts


def _grab_raw_text(action_result, txt_file):
    """ This function will actually really work for any file which is basically raw text.
        html, rtf, and the list could go on
    """
    try:
        fp = file(txt_file, 'r')
        text = fp.read()
        fp.close()
        return phantom.APP_SUCCESS, text
    except Exception as e:
        return action_result.set_status(phantom.APP_ERROR, e), None


def _pdf_to_text(action_result, pdf_file):
    try:
        pagenums = set()
        output = StringIO()
        manager = PDFResourceManager()
        converter = TextConverter(manager, output, laparams=LAParams())
        interpreter = PDFPageInterpreter(manager, converter)

        infile = file(pdf_file, 'rb')
        for page in PDFPage.get_pages(infile, pagenums):
            interpreter.process_page(page)
        infile.close()
        converter.close()
        text = output.getvalue()
        output.close
        return text
    except Exception as e:
        return action_result.set_status(phantom.APP_ERROR, "Failed to parse pdf: {0}".format(str(e))), None


def _docx_to_text(action_result, docx_file):
    """ docx is literally a zip file, and all the words in the document are in one xml document
        doc does not work this way at all
    """
    try:
        zf = zipfile.ZipFile(docx_file)
        fp = zf.open('word/document.xml')
        txt = fp.read()
        fp.close()
        root = etree.fromstring(txt)
        doc_txt = ""
        for text_el in root.iter('{*}t'):
            doc_txt += text_el.text
        return phantom.APP_SUCCESS, doc_txt
    except Exception as e:
        return action_result.set_status(phantom.APP_ERROR, "Failed to parse docx: {0}".format(str(e))), None


def _csv_to_text(action_result, csv_file):
    """ This function really only exists due to a misunderating on how word boundries (\b) work
        As it turns out, only word characters can invalidate word boundries. So stuff like commas,
        brackets, gt and lt signs, etc. do not
    """
    text = ""
    try:
        fp = open(csv_file, 'rb')
        reader = csv.reader(fp)
        for row in reader:
            text += ' '.join(row)
            text += ' '  # The humanity of always having a trailing space
        fp.close()
        return phantom.APP_SUCCESS, text
    except Exception as e:
        return action_result.set_status(phantom.APP_ERROR, "Failed to parse csv: {0}".format(str(e))), None


def _html_to_text(action_result, html_file):
    """ Similar to CSV, this is also unnecessary. It will trim /some/ of that fat from a normal HTML, however
    """
    try:
       fp = open(html_file, 'r')
       html_text = fp.read()
       soup = BeautifulSoup(html_text, 'html.parser')
       read_text = soup.findAll(text=True)
       text = ' '.join(read_text)
       fp.close()
       return text
    except Exception as e:
        return action_result.set_status(phantom.APP_ERROR, "Failed to parse html: {0}".format(str(e))), None


def _join_thread(base_connector, thread):
    base_connector._lock.acquire()
    base_connector._done = True
    base_connector._lock.release()
    thread.join()


def _wait_for_parse(base_connector):
    i = 0
    base_msg = "Parsing PDF document"
    while True:
        base_connector._lock.acquire()
        if (base_connector._done):
            base_connector._lock.release()
            break
        base_connector.send_progress(base_msg + '.' * i)
        base_connector._lock.release()
        i = i % 5 + 1
        time.sleep(1)
    return


def parse_file(base_connector, action_result, file_info):
    """ Parse a non-email file """
    raw_text = None
    if (file_info['type'] == 'pdf'):
        """ Parsing a PDF document over like, 10 pages starts to take a while
            (A 80 something page document took like 5 - 10 minutes)
            The thread is nice because it shows a constantly changing message,
            which shows that the app isn't frozen, but it also stops watchdog
            from terminating the app
        """
        thread = threading.Thread(target=_wait_for_parse, args=[base_connector])
        thread.start()
        ret_val, raw_text = _pdf_to_text(action_result, file_info['path'])
        _join_thread(base_connector, thread)
    elif (file_info['type'] == 'txt'):
        ret_val, raw_text = _grab_raw_text(action_result, file_info['path'])
    elif (file_info['type'] == 'docx'):
        ret_val, raw_text = _docx_to_text(action_result, file_info['path'])
    elif (file_info['type'] == 'csv'):
        ret_val, raw_text = _csv_to_text(action_result, file_info['path'])
        base_connector.debug_print(raw_text)
    elif (file_info['type'] == 'html'):
        ret_val, raw_text = _html_to_text(action_result, file_info['path'])
    else:
        return action_result.set_status(phantom.APP_ERROR, "Unexpected file type"), None
    if phantom.is_fail(ret_val):
        return ret_val, None

    tiocp = TextIOCParser()
    base_connector.save_progress('Parsing for IOCs')
    try:
        artifacts = tiocp.parse_to_artifacts(raw_text)
    except Exception as e:
        return action_result.set_status(phantom.APP_ERROR, str(e)), None
    base_connector.debug_print(artifacts)
    return phantom.APP_SUCCESS, {'artifacts': artifacts}
