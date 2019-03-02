# -*- coding: utf-8 -*-

# FOGLAMP_BEGIN
# See: http://foglamp.readthedocs.io/
# FOGLAMP_END

""" Test Configuration REST API """


import http.client
import json


__author__ = "Praveen Garg"
__copyright__ = "Copyright (c) 2019 Dianomic Systems"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"


class TestConfiguration:

    def test_default(self, foglamp_url, reset_and_start_foglamp):
        conn = http.client.HTTPConnection(foglamp_url)

        conn.request("GET", '/foglamp/category')
        r = conn.getresponse()
        assert 200 == r.status
        r = r.read().decode()
        jdoc = json.loads(r)
        assert len(jdoc)

        conn.request("GET", '/foglamp/category?root=true')
        r = conn.getresponse()
        assert 200 == r.status
        r = r.read().decode()
        jdoc = json.loads(r)
        cats = jdoc["categories"]
        assert 3 == len(cats)
        assert {'key': 'General', 'displayName': 'General', 'description': 'General'} == cats[0]
        assert {'key': 'Advanced', 'displayName': 'Advanced', 'description': 'Advanced'} == cats[1]
        assert {'key': 'Utilities', 'displayName': 'Utilities', 'description': 'Utilities'} == cats[2]

        conn.request("GET", '/foglamp/category?root=true&children=true')
        r = conn.getresponse()
        assert 200 == r.status
        r = r.read().decode()
        jdoc = json.loads(r)
        assert len(jdoc["categories"])
        expected = [
            {'children': [{'children': [], 'displayName': 'Admin API', 'key': 'rest_api', 'description': 'FogLAMP Admin and User REST API'},
                          {'children': [], 'displayName': 'FogLAMP Service', 'key': 'service', 'description': 'FogLAMP Service'}
                          ],
             'displayName': 'General', 'key': 'General', 'description': 'General'},
            {'children': [{'children': [], 'displayName': 'Scheduler', 'key': 'SCHEDULER', 'description': 'Scheduler configuration'},
                          {'children': [], 'displayName': 'Service Monitor', 'key': 'SMNTR', 'description': 'Service Monitor'}],
             'displayName': 'Advanced', 'key': 'Advanced', 'description': 'Advanced'},
            {'children': [],
             'displayName': 'Utilities', 'key': 'Utilities', 'description': 'Utilities'}]
        assert expected == jdoc["categories"]

    def test_get_category(self, foglamp_url):
        conn = http.client.HTTPConnection(foglamp_url)
        conn.request("GET", '/foglamp/category/rest_api')
        r = conn.getresponse()
        assert 200 == r.status
        r = r.read().decode()
        jdoc = json.loads(r)
        assert len(jdoc)
        for k, v in jdoc.items():
            assert 'type' in v
            assert 'value' in v
            assert 'default' in v
            assert 'description' in v

            assert 'displayName' in v

    def test_create_category(self, foglamp_url):
        pass

    def test_get_category_item(self, foglamp_url):
        pass

    def test_set_configuration_item(self, foglamp_url):
        pass

    def test_update_configuration_item_bulk(self, foglamp_url):
        pass

    def test_add_configuration_item(self, foglamp_url):
        pass

    def test_delete_configuration_item_value(self, foglamp_url):
        pass

    def test_get_child_category(self, foglamp_url):
        pass

    def test_create_child_category(self, foglamp_url):
        pass

    def test_delete_child_category(self, foglamp_url):
        pass

    def test_delete_parent_category(self, foglamp_url):
        pass

    def test_upload_script(self, foglamp_url):
        pass
