import sys
import os
import time
import json
import hashlib
import calendar
from datetime import datetime, timedelta
from splunklib.modularinput import *

# Import our own libraries, and prefer them to Splunk's older versions
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/lib/")
from OTXv2.OTXv2 import OTXv2

class OTXModularInput(Script):

	def get_scheme(self):
		scheme = Scheme("Open Threat Exchange")
		scheme.description = "Retrieve Pulses from OTX"
		scheme.use_external_validation = False
		scheme.use_single_instance = False

		api_key = Argument("api_key")
		api_key.data_type = Argument.data_type_string
		api_key.title = "API key"
		api_key.description = "Your Open Threat Exchange API key"
		api_key.required_on_create = True
		api_key.required_on_edit = True
		scheme.add_argument(api_key)

		backfill_days = Argument("backfill_days")
		backfill_days.data_type = Argument.data_type_number
		backfill_days.title = "Backfill days"
		backfill_days.description = "The number of days to backfill Pulses for on first run"
		backfill_days.required_on_create = True
		backfill_days.required_on_edit = True
		scheme.add_argument(backfill_days)

		proxy = Argument("proxy")
		proxy.data_type = Argument.data_type_string
		proxy.title = "HTTP Proxy"
		proxy.description = "A HTTP proxy URL if it is required"
		proxy.required_on_create = False
		proxy.required_on_edit = False
		scheme.add_argument(proxy)

		return scheme

	def stream_events(self, inputs, ew):
		for input_name, input_item in inputs.inputs.iteritems():

			api_key = str(input_item["api_key"])
			backfill_days = int(input_item["backfill_days"])
			if "proxy" in input_item:
				proxy = str(input_item["proxy"])
			else:
				proxy = ""
			index = str(input_item["index"])
			host = str(input_item["host"])
			run_time = time.time()

			otx = OTXv2(api_key, proxy)

			ew.log(ew.INFO, "Beginning poll of OTX with API key: %s" % api_key)

			try:
				checkpoint_data = self.get_checkpoint_data(inputs.metadata["checkpoint_dir"], input_name)
			except IOError:
				checkpoint_data = None

			# Try to load the last ran date from the checkpoint data
			if checkpoint_data is not None and 'last_ran' in checkpoint_data:
				last_ran = checkpoint_data['last_ran']
			else:
				last_ran = None

		 	if last_ran is not None:
		 		since = datetime.utcfromtimestamp(last_ran)
		 	else:
		 		since = datetime.now() - timedelta(days = backfill_days)

			ew.log(ew.INFO, "Retrieving subscribed pulses since: %s" % str(since))

			pulses = otx.getall(modified_since=since.isoformat(), iter=True)

			pulse_count = 0
			indicator_count = 0
			for pulse in pulses:
				indicators = pulse.pop('indicators', None)

				timeparts = pulse['modified'].split('.')
				time_parsed = self.utc_to_local(datetime.strptime(timeparts[0], "%Y-%m-%dT%H:%M:%S"))
				xtime = time.mktime(time_parsed.timetuple())

				e = Event(
					data = json.dumps(pulse),
					stanza = input_name,
					time = xtime,
					host = host,
					index = index,
					source = input_name,
					sourcetype = "otx:pulse",
					done = True
				)

				ew.write_event(e)

				pulse_count = pulse_count + 1

				for indicator in indicators:
					indicator['pulse_id'] = pulse['id']

					timeparts = indicator['created'].split('.')
					time_parsed = self.utc_to_local(datetime.strptime(timeparts[0], "%Y-%m-%dT%H:%M:%S"))
					xtime = time.mktime(time_parsed.timetuple())

					e = Event(
						data = json.dumps(indicator),
						stanza = input_name,
						time = xtime,
						host = host,
						index = index,
						source = input_name,
						sourcetype = "otx:indicator",
						done = True
					)

					ew.write_event(e)

					indicator_count = indicator_count + 1

			self.save_checkpoint_data(inputs.metadata["checkpoint_dir"], input_name,  { 'last_ran': run_time })

			ew.log(ew.INFO, "Completed polling. Logged %d pulses and %d indicators." % (pulse_count, indicator_count))

	def utc_to_local(self, utc_dt):
	    timestamp = calendar.timegm(utc_dt.timetuple())
	    local_dt = datetime.fromtimestamp(timestamp)
	    assert utc_dt.resolution >= timedelta(microseconds=1)
	    return local_dt.replace(microsecond=utc_dt.microsecond)

	def get_checkpoint_data(self, checkpoint_dir, stanza="(undefined)"):
	    fp = None

	    try:
	        fp = open(self.get_file_path(checkpoint_dir, stanza) )
	        checkpoint_dict = json.load(fp)
	        return checkpoint_dict
	    finally:
	        if fp is not None:
	            fp.close()

	def save_checkpoint_data(self, checkpoint_dir, stanza, data):
	    fp = None

	    try:
	        fp = open(self.get_file_path(checkpoint_dir, stanza), 'w' )
	        json.dump(data, fp)
	    finally:
	        if fp is not None:
	            fp.close()

	def get_file_path(self, checkpoint_dir, stanza):
		return os.path.join( checkpoint_dir, hashlib.sha224(stanza).hexdigest() + ".json" )


if __name__ == "__main__":
	sys.exit(OTXModularInput().run(sys.argv))
