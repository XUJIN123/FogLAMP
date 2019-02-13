# -*- coding: utf-8 -*-

# FOGLAMP_BEGIN
# See: http://foglamp.readthedocs.io/
# FOGLAMP_END

""" Test Configuration REST API """


import http.client
import json
import pytest


__author__ = "Praveen Garg"
__copyright__ = "Copyright (c) 2019 Dianomic Systems"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"


@pytest.fixture(scope='class')
def reset_start_foglamp_once(reset_and_start_foglamp):
    pass


@pytest.mark.usefixtures('reset_start_foglamp_once')
class TestConfiguration:

    def test_get_categories_default(self, foglamp_url):
        conn = http.client.HTTPConnection(foglamp_url)

        conn.request("GET", '/foglamp/category')
        r = conn.getresponse()
        assert 200 == r.status
        r = r.read().decode()
        jdoc = json.loads(r)
        assert len(jdoc)  # verify actual

        conn.request("GET", '/foglamp/category?root=true')
        r = conn.getresponse()
        assert 200 == r.status
        r = r.read().decode()
        jdoc = json.loads(r)
        assert len(jdoc)  # verify actual

        conn.request("GET", '/foglamp/category?root=true&children=true')
        r = conn.getresponse()
        assert 200 == r.status
        r = r.read().decode()
        jdoc = json.loads(r)
        assert len(jdoc["categories"])  # verify actual

    def test_get_category(self, foglamp_url):
        pass

    # def test_create_category(self, foglamp_url):
    #     pass
    #
    # def test_get_category_item(self, foglamp_url):
    #     pass
    #
    # def test_set_configuration_item(self, foglamp_url):
    #     pass
    #
    # def test_update_configuration_item_bulk(self, foglamp_url):
    #     pass
    #
    # def test_add_configuration_item(self, foglamp_url):
    #     pass
    #
    # def test_delete_configuration_item_value(self, foglamp_url):
    #     pass
    #
    # def test_get_child_category(self, foglamp_url):
    #     pass
    #
    # def test_create_child_category(self, foglamp_url):
    #     pass
    #
    # def test_delete_child_category(self, foglamp_url):
    #     pass
    #
    # def test_delete_parent_category(self, foglamp_url):
    #     pass
    #
    # def test_upload_script(self, foglamp_url):
    #     pass
