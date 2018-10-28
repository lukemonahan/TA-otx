import sys
import os
import time
from datetime import datetime, timedelta
import json

from modular_input import ModularInput, DurationField, IntegerField, Field

# Import our own libraries, and prefer them to Splunk's older versions
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/lib/")

from OTXv2.OTXv2 import OTXv2

class OTXModularInput(ModularInput):

	def __init__(self):

		scheme_args = {'title': "Open Threat Exchange",
					   'description': "Retrieve Pulses from OTX",
					   'use_external_validation': "true",
					   'streaming_mode': "xml",
					   'use_single_instance': "true"}

		args = [
				Field("api_key", "API key", "Your Open Threat Exchange API key", empty_allowed=False),
				IntegerField("backfill_days", "Backfill days", "The number of days to backfill Pulses for on first run", empty_allowed=False),
				DurationField("interval", "Interval", "The interval defining how often to check for updated Pulses; can include time units (e.g. 15m for 15 minutes, 8h for 8 hours)", empty_allowed=False)
				]

		ModularInput.__init__( self, scheme_args, args, logger_name='otx' )

	def create_event_string(self, data_dict, stanza, sourcetype, source, index, host=None, unbroken=False, close=False, encapsulate_value_in_double_spaces=False):
		data_str = json.dumps(data_dict)

		# Make the event
		event_dict = {'stanza': stanza,
					  'data' : data_str}
		
		if index is not None:
			event_dict['index'] = index
			
		if sourcetype is not None:
			event_dict['sourcetype'] = sourcetype
			
		if source is not None:
			event_dict['source'] = source
			
		if host is not None:
			event_dict['host'] = host

		if 'modified' in data_dict:
			xtime = data_dict['modified']
		elif 'created' in data_dict:
			xtime = data_dict['created']

		timeparts = xtime.split('.')
		xtime_parsed = datetime.strptime(timeparts[0] + " GMT", "%Y-%m-%dT%H:%M:%S %Z")
		event_dict['time'] = time.mktime(xtime_parsed.timetuple())

		event = self._create_event(self.document, 
								   params=event_dict,
								   stanza=stanza,
								   unbroken=unbroken,
								   close=close)
		
		# If using unbroken events, the last event must have been 
		# added with a "</done>" tag.
		return self._print_event(self.document, event)


	def run(self, stanza, cleaned_params, input_config):

		interval = cleaned_params["interval"]
		api_key = cleaned_params["api_key"]
		backfill_days = cleaned_params["backfill_days"]
		index = cleaned_params.get("index", "default")
		host = cleaned_params.get("host", None)
		source = stanza

                run_time = time.time()

		otx = OTXv2(api_key)

		if self.needs_another_run(input_config.checkpoint_dir, stanza, interval):

			# Get the date of the latest pulse imported
			try:
				checkpoint_data = self.get_checkpoint_data(input_config.checkpoint_dir, stanza, throw_errors=True)
			except IOError:
				checkpoint_data = None
			except ValueError:
				self.logger.exception("Exception generated when attempting to load the checkpoint data")
				checkpoint_data = None

			# Try to load the last ran date from the checkpoint data
			if checkpoint_data is not None and 'last_ran' in checkpoint_data:
				last_ran = checkpoint_data['last_ran']
			else:
				last_ran = None

		 	if last_ran is not None:
		 		since = datetime.fromtimestamp(last_ran)
		 	else:
		 		since = datetime.now() - timedelta(days = backfill_days)

			pulses = otx.getall(modified_since=since, iter=True)

			for pulse in pulses:
				indicators = pulse.pop('indicators', None)
				self.output_event(pulse, stanza, index=index, source=source, sourcetype="otx:pulse", host=host, unbroken=False, close=True)
				for indicator in indicators:
					indicator['pulse_id'] = pulse['id']
					self.output_event(indicator, stanza, index=index, source=source, sourcetype="otx:indicator", host=host, unbroken=False, close=True)

			self.save_checkpoint_data(input_config.checkpoint_dir, stanza,  { 'last_ran': run_time })


if __name__ == '__main__':
	try:
		otx_input = OTXModularInput()
		otx_input.execute()
		sys.exit(0)
	except Exception as exception:

		# This logs general exceptions that would have been unhandled otherwise (such as coding errors)
		if otx_input is not None:
			otx_input.logger.exception("Unhandled exception was caught, this may be due to a defect in the script")

		raise exception
