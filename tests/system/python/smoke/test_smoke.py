# -*- coding: utf-8 -*-

# FOGLAMP_BEGIN
# See: http://foglamp.readthedocs.io/
# FOGLAMP_END

""" Test system/python/test_smoke.py

"""
import os
import subprocess
import http.client
import json
import time
import pytest
import configparser

__author__ = "Vaibhav Singhal"
__copyright__ = "Copyright (c) 2019 Dianomic Systems"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

TEMPLATE_NAME = "template.json"
SENSOR_VALUE = 10

config = configparser.RawConfigParser()
config.read('config/example.cfg')
BASE_URI = config.get('basic', 'foglamp_url')
WAIT_TIME = int(config.get('basic', 'wait_time'))
SOUTH_BRANCH = config.get('south', 'south_branch')
ASSET_NAME = config.get('south', 'asset_name')
SERVICE_NAME = config.get('south', 'service_name')


@pytest.fixture
def start_south_coap(reset_and_start_foglamp, add_south, remove_data_file, remove_directories,
                     south_plugin="coap"):
    """ This fixture clone a south repo and starts both south and north instance
        reset_and_start_foglamp: Fixture that resets and starts foglamp, no explicit invocation, called at start
        add_south: Fixture that adds a south service with given configuration
        remove_data_file: Fixture that remove data file created during the tests
        remove_directories: Fixture that remove directories created during the tests"""

    # Define the template file for fogbench
    fogbench_template_path = os.path.join(
        os.path.expandvars('${FOGLAMP_ROOT}'), 'data/{}'.format(TEMPLATE_NAME))
    with open(fogbench_template_path, "w") as f:
        f.write(
            '[{"name": "%s", "sensor_values": '
            '[{"name": "sensor", "type": "number", "min": %d, "max": %d, "precision": 0}]}]' % (
                ASSET_NAME, SENSOR_VALUE, SENSOR_VALUE))

    add_south(south_plugin, SOUTH_BRANCH, BASE_URI, service_name=SERVICE_NAME)

    yield start_south_coap

    # Cleanup code that runs after the caller test is over
    remove_data_file(fogbench_template_path)
    remove_directories("/tmp/foglamp-south-{}".format(south_plugin))


def test_smoke(start_south_coap):
    """ Test that data is inserted in FogLAMP
        start_south_coap: Fixture that starts FogLAMP with south coap plugin
        Assertions:
            on endpoint GET /foglamp/asset
            on endpoint GET /foglamp/asset/<asset_name>
    """

    conn = http.client.HTTPConnection(BASE_URI)
    time.sleep(WAIT_TIME)
    subprocess.run(["cd $FOGLAMP_ROOT/extras/python; python3 -m fogbench -t ../../data/{}; cd -".format(TEMPLATE_NAME)],
                   shell=True, check=True)
    time.sleep(WAIT_TIME)
    conn.request("GET", '/foglamp/asset')
    r = conn.getresponse()

    assert 200 == r.status
    r = r.read().decode()
    retval = json.loads(r)
    assert len(retval) == 1
    assert ASSET_NAME == retval[0]["assetCode"]
    assert 1 == retval[0]["count"]

    conn.request("GET", '/foglamp/asset/{}'.format(ASSET_NAME))
    r = conn.getresponse()
    assert 200 == r.status
    r = r.read().decode()
    retval = json.loads(r)
    assert {'sensor': SENSOR_VALUE} == retval[0]["reading"]
