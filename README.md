Add-on for Open Threat Exchange
-------------------------------

Get Open Threat Exchange data into Splunk.

This add-on polls the OTX API and indexes pulses, and their related indicators, into Splunk.

See also the partner app SA-otx which uses this data and adds threat indicators into the Splunk ES threat collections.

To use this add-on:

1. Sign-up to OTX: https://otx.alienvault.com -- You will automatically be subscribed to public threat feeds published by AlienVault, but you can also sign up to follow threats from other groups using OTX. 
1. Retrieve your API key at: https://otx.alienvault.com/api
1. Create the index "otx"
1. In Splunk, navigate to Inputs -> Open Threat Exchange and enter your API key. At this point you can also tune the collection interval, backfill period and other properties
1. "Enable" the OTX input in Splunk

At this point you should soon be able to see OTX data by searching:

`index=otx sourcetype=otx:pulse`

`index=otx sourcetype=otx:indicator`

The otx:indicator events contain a `pulse_id`, which link it to the `id` of a corresponding `otx:pulse`.
