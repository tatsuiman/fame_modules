import os
import sys
import importlib

from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
import hashlib

try:
    from pymisp import PyMISP
    HAVE_MISP = True
except ImportError:
    HAVE_MISP = False


class MISP(ProcessingModule):

    name = "MISP"
    description = "MISP API queries."

    config = [
            {
                'name': 'api_endpoint',
                'type': 'str',
                'default': 'http://127.0.0.1/',
                'description': "URL of MISP API endpoint."
            },
            {
                'name': 'api_key',
                'type': 'str',
                'description': 'MISP API key',
            }
    ]

    def initialize(self):
        if not HAVE_MISP:
            raise ModuleInitializationError(self, "Missing dependency: pymisp")
        self.results = {}

    def each_with_type(self, target, file_type):
        search_result = False
        self.misp = PyMISP(self.api_endpoint, self.api_key, False)
        if file_type == 'url':
            misp_result = self.misp.search_all(keyword)
            if 'response' in misp_result:
                # Extract the MISP event details
                for e in misp_result['response']:
                    search_result = True
                    misp_event = e['Event']
                    for tag in misp_event['Tag']:
                        self.add_tag(tag['name'])
                    Attribute = misp_event['Attribute']
                    self.results[misp_event['info']] = self.results.get(misp_event['info'], [])
                    for a in Attribute:
                        self.results[misp_event['info']].append({
                            'date':misp_event['date'],
                            'comment':a.get('comment'), 
                            'value':a.get('value'),
                            'type':a.get('type'),
                            'category':a.get('category')
                        })
        else:
            with open(target) as f:
                data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                search_content = [md5, sha256]
                for keyword in search_content:
                    misp_result = self.misp.search_all(keyword)
                    # Process the response and events
                    if 'response' in misp_result:
                        # Extract the MISP event details
                        for e in misp_result['response']:
                            search_result = True
                            misp_event = e['Event']
                            for tag in misp_event['Tag']:
                                self.add_tag(tag['name'])
                            Attribute = misp_event['Attribute']
                            self.results[misp_event['info']] = self.results.get(misp_event['info'], [])
                            for a in Attribute:
                                self.results[misp_event['info']].append({
                                    'date':misp_event['date'],
                                    'comment':a.get('comment'), 
                                    'value':a.get('value'),
                                    'type':a.get('type'),
                                    'category':a.get('category')
                                })
        return search_result
