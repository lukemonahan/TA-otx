
# encoding = utf-8

import os
import sys
import time
import datetime

import json
import hashlib
import calendar
from datetime import datetime, timedelta


def utc_to_local(utc_dt):
    timestamp = calendar.timegm(utc_dt.timetuple())
    local_dt = datetime.fromtimestamp(timestamp)
    assert utc_dt.resolution >= timedelta(microseconds=1)
    return local_dt.replace(microsecond=utc_dt.microsecond)

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    #api_key = definition.parameters.get('api_key', None)
    #backfill_days = definition.parameters.get('backfill_days', None)
    pass

def collect_events(helper, ew):

    api_key = helper.get_arg('api_key')
    backfill_days = int(helper.get_arg('backfill_days'))

    run_time = time.time()
    
    last_ran = helper.get_check_point('last_ran')

    if last_ran is not None:
 	    since = datetime.utcfromtimestamp(last_ran)
    else:
 	    since = datetime.now() - timedelta(days = backfill_days)  
 		
    helper.log_info("Retrieving subscribed pulses since: %s" % str(since))	
 		
    response = helper.send_http_request(
 	    'https://otx.alienvault.com/api/v1/pulses/subscribed', 
        'GET', 
        parameters = {'modified_since' : since }, 
        headers = { 'X-OTX-API-KEY' : api_key }, 
        verify=True, 
        use_proxy=True
    )
    
    response.raise_for_status()
    
    pulses = response.json()['results']
    
    pulse_count = 0
    indicator_count = 0
    for pulse in pulses:
        
        indicators = pulse.pop('indicators', None)

        timeparts = pulse['modified'].split('.')
        time_parsed = utc_to_local(datetime.strptime(timeparts[0], "%Y-%m-%dT%H:%M:%S"))
        xtime = time.mktime(time_parsed.timetuple())

        e = helper.new_event(
            data = json.dumps(pulse),
            time = xtime,
            sourcetype = "otx:pulse",
            index = helper.get_output_index(),
            done = True
		)
        ew.write_event(e)
		
        pulse_count = pulse_count + 1

        for indicator in indicators:
            indicator['pulse_id'] = pulse['id']
            
            timeparts = indicator['created'].split('.')
            time_parsed = utc_to_local(datetime.strptime(timeparts[0], "%Y-%m-%dT%H:%M:%S"))
            xtime = time.mktime(time_parsed.timetuple())
            
            e = helper.new_event(
                data = json.dumps(indicator),
                time = xtime,
                sourcetype = "otx:indicator",
                index = helper.get_output_index(),
                done = True
            )
            ew.write_event(e)
            
            indicator_count = indicator_count + 1

    helper.log_info("Completed polling. Logged %d pulses and %d indicators." % (pulse_count, indicator_count))
 		
    helper.save_check_point('last_ran', run_time)
    #helper.delete_check_point('last_ran')