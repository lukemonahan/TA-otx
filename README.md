Add-on for Open Threat Exchange
-------------------------------

Get Open Threat Exchange data into Splunk.

This add-on polls the OTX API and indexes pulses, and their related indicators, into Splunk.

You can then use these indicators and pulses you see fit, however if you are a Splunk for Enterprise Security user you should also get the partner app SA-otx, which uses this data and adds threat indicators into the Splunk ES threat collections.

To use this add-on:

1. Sign-up to OTX: https://otx.alienvault.com -- You will automatically be subscribed to public threats published by AlienVault, but you can also sign up to other useful groups and users. It's recommended that you subscribe to the groups and users you wish to follow now, so that the initial backfill gets all your subscribed pulses.
1. Retrieve your API key at: https://otx.alienvault.com/api
1. Create the Splunk index "otx"
1. Navigate to the "Addon for OTX" app in Splunk
1. Create an input for OTX pulses and indicators using your OTX key and the new index you created

Soon after this point you should soon be able to see OTX data by searching:

`index=otx sourcetype=otx:pulse`

`index=otx sourcetype=otx:indicator`

Of note:
* The `otx:indicator` events contain a `pulse_id`, which link it to the `id` of a corresponding `otx:pulse`.
* The input picks up any modified pulses since last poll, so you may wish to use `| dedup id` to limit to the latest reported details of an individual `otx:pulse`

