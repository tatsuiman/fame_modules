import os
import sys
import importlib

from fame.common.constants import VENDOR_ROOT
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
import magic

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False


class YaraScan(ProcessingModule):

    name = "yara_scan"
    description = "yara scan file"

    def initialize(self):
        if not HAVE_YARA:
            raise ModuleInitializationError(self, "Missing dependency: yara")

        self.results = {}

    def yara_scan(self, yar_rule_path, data):
        matches = []
        try:
            rules = yara.compile(yar_rule_path)
            matches = rules.match(data=data)
            if len(matches) > 0:
                return matches
        except :
            self.log('error', 'Yara rule error. [%s]' % yar_rule_path)
        return None
        
    def each_with_type(self, target, file_type):
        self.results = []
        match_result = False
        if file_type == 'url':
            return False
        file_mapping = {
            'Yara-Rules/Webshells_index.yar': ['html', 'javascript'],
            'Yara-Rules/Exploit-Kits_index.yar': ['html', 'javascript', 'jar'],
            'Yara-Rules/Exploit-Kits_index.yar': ['html', 'javascript', 'jar'],
            'Yara-Rules/Malicious_Documents_index.yar':['word', 'html', 'excel', 'powerpoint', 'pdf', 'rtf'],
            'Yara-Rules/email_index.yar': ['eml'],
            'Yara-Rules/Mobile_Malware_index.yar': ['apk', 'dex'],
            'Yara-Rules/malware_index.yar': ['executable', 'jar'],
            'Yara-Rules/Packers_index.yar': ['executable', 'jar'],
            'Yara-Rules/Antidebug_AntiVM_index.yar':['executable', 'jar'],
            'Yara-Rules/CVE_Rules_index.yar':['executable', 'jar'],
            'Yara-Rules/index.yar':['data'],
        }
        for yar_file in file_mapping.keys():
            if file_type in file_mapping[yar_file]:
                yar_rule_path = os.path.join(VENDOR_ROOT, yar_file)
                if not os.path.exists(yar_rule_path):
                    self.log('error', '%s not found.' % yar_rule_path)
                else:
                    with open(target, 'r') as f:
                        data = f.read()
                        matches = self.yara_scan(yar_rule_path, data)
                        if matches is not None:
                            for match in matches:
                                self.add_tag(match.rule)
                                self.results.append(match.rule)
                            match_result = True
        return match_result
