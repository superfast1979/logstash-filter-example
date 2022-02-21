# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require "logstash/devutils/rspec/spec_helper"

def check_type_3(events, i, j)
	expect(events[i].get("[ospf][timestamp]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time_epoch]"))
	expect(events[i].get("[ospf][utc_time]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time]"))
	expect(events[i].get("[ospf][timestamp]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time_epoch]"))
	expect(events[i].get("[ospf][lsa_type]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa]")[j])
	expect(events[i].get("[ospf][lsa_age]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_age]")[j])
	expect(events[i].get("[ospf][adv_router]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_advrouter]")[j])
	expect(events[i].get("[ospf][prefix-id]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_id]")[j])
	expect(events[i].get("[ospf][netmask]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_asbr_netmask]")[j])
	expect(events[i].get("[ospf][ospf_metric]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_metric]")[j])
	expect(events[i].get("[ospf][lsa_down_bit]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_dn]")[j])
	expect(events[i].get("[ospf][lsa_external_bit]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_e]")[j])
	expect(events[i].get("[ospf][extra]")).to eq("")
end
