# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ospfPackets"
require "json"

describe LogStash::Filters::Ospfpackets do
	
	describe Array do
	  it "should be empty when first created" do
	    expect(subject).to be_empty
	  end
	end

	describe "subject valid" do
	  subject { [1, 2, 3] }
	  it "should be setted when first created" do
	    expect(subject).to eq([1, 2, 3])
	  end
	end

    describe String do
      it "is available as described_class" do
        expect(described_class).to eq(String)
      end
    end
   
    describe LogStash::Filters::Ospfpackets do
    	subject { described_class.new(config) }
		let(:config) { Hash.new }
		let(:event) { LogStash::Event.new(data) }
		let(:data) { { "json_parsed" => message } }
		let(:message) { JSON.parse('{"timestamp":"1643721667955","layers":{"frame":{"frame_frame_encap_type":"25","frame_frame_time":"2022-02-01T13:21:07.958804000Z","frame_frame_offset_shift":"0.000000000","frame_frame_time_epoch":"1643721667.958804000","frame_frame_time_delta":"0.000000000","frame_frame_time_delta_displayed":"0.000000000","frame_frame_time_relative":"0.000000000","frame_frame_number":"1","frame_frame_len":"196","frame_frame_cap_len":"196","frame_frame_marked":false,"frame_frame_ignored":false,"frame_frame_protocols":"sll:ip:ospf"},"sll":{"sll_sll_pkttype":"0","sll_sll_hatype":"778","sll_sll_halen":"0","sll_sll_unused":"00:00:00:00:00:00:00:00","sll_sll_gretype":"0x00000800"},"ip":{"ip_ip_version":"4","ip_ip_hdr_len":"20","ip_ip_dsfield":"0x000000c0","ip_ip_dsfield_dscp":"48","ip_ip_dsfield_ecn":"0","ip_ip_len":"180","ip_ip_id":"0x00005f3e","ip_ip_flags":"0x00000000","ip_ip_flags_rb":false,"ip_ip_flags_df":false,"ip_ip_flags_mf":false,"ip_ip_frag_offset":"0","ip_ip_ttl":"1","ip_ip_proto":"89","ip_ip_checksum":"0x0000163b","ip_ip_checksum_status":"2","ip_ip_src":"177.177.177.1","ip_ip_addr":["177.177.177.1","224.0.0.5"],"ip_ip_src_host":"177.177.177.1","ip_ip_host":["177.177.177.1","224.0.0.5"],"ip_ip_dst":"224.0.0.5","ip_ip_dst_host":"224.0.0.5"},"ospf":{"ospf_ospf_header":null,"ospf_ospf_version":"2","ospf_ospf_msg":"4","ospf_ospf_msg_lsupdate":true,"ospf_ospf_packet_length":"160","ospf_ospf_srcrouter":"124.0.0.7","ospf_ospf_area_id":"0.0.0.8","ospf_ospf_checksum":"0x00006b5f","ospf_ospf_auth_type":"0","ospf_ospf_auth_none":"00:00:00:00:00:00:00:00","text":["LSA-type 1 (Router-LSA), len 132","Type: Stub     ID: 9.9.9.1         Data: 255.255.255.255 Metric: 1","Type: Stub     ID: 192.168.100.64  Data: 255.255.255.252 Metric: 10","Type: Stub     ID: 192.168.100.68  Data: 255.255.255.252 Metric: 10","Type: Stub     ID: 192.168.100.72  Data: 255.255.255.252 Metric: 10","Type: Stub     ID: 192.168.100.20  Data: 255.255.255.252 Metric: 10","Type: PTP      ID: 24.0.0.4        Data: 192.168.100.26  Metric: 65535","Type: Stub     ID: 192.168.100.24  Data: 255.255.255.252 Metric: 10","Type: PTP      ID: 124.0.0.7       Data: 192.168.100.78  Metric: 65535","Type: Stub     ID: 192.168.100.76  Data: 255.255.255.252 Metric: 10"],"ospf_ospf_ls_number_of_lsas":"1","ospf_ospf_lsa_age":"2","ospf_ospf_lsa_donotage":"0","ospf_ospf_v2_options":"0x00000028","ospf_ospf_v2_options_dn":false,"ospf_ospf_v2_options_o":false,"ospf_ospf_v2_options_dc":true,"ospf_ospf_v2_options_l":false,"ospf_ospf_v2_options_n":true,"ospf_ospf_v2_options_mc":false,"ospf_ospf_v2_options_e":false,"ospf_ospf_v2_options_mt":false,"ospf_ospf_lsa":"1","ospf_ospf_lsa_router":true,"ospf_ospf_lsa_id":"24.0.0.5","ospf_ospf_advrouter":"24.0.0.5","ospf_ospf_lsa_seqnum":"0x800004bf","ospf_ospf_lsa_chksum":"0x0000525c","ospf_ospf_lsa_length":"132","ospf_ospf_v2_router_lsa_flags":"0x00000002","ospf_ospf_v2_router_lsa_flags_h":false,"ospf_ospf_v2_router_lsa_flags_n":false,"ospf_ospf_v2_router_lsa_flags_w":false,"ospf_ospf_v2_router_lsa_flags_v":false,"ospf_ospf_v2_router_lsa_flags_e":true,"ospf_ospf_v2_router_lsa_flags_b":false,"ospf_ospf_lsa_number_of_links":"9","ospf_ospf_lsa_router_linkid":["9.9.9.1","192.168.100.64","192.168.100.68","192.168.100.72","192.168.100.20","24.0.0.4","192.168.100.24","124.0.0.7","192.168.100.76"],"ospf_ospf_lsa_router_linkdata":["255.255.255.255","255.255.255.252","255.255.255.252","255.255.255.252","255.255.255.252","192.168.100.26","255.255.255.252","192.168.100.78","255.255.255.252"],"ospf_ospf_lsa_router_linktype":["3","3","3","3","3","1","3","1","3"],"ospf_ospf_lsa_router_nummetrics":["0","0","0","0","0","0","0","0","0"],"ospf_ospf_lsa_router_metric0":["1","10","10","10","10","65535","10","65535","10"]}}}') }
		
		before(:each) do
		  subject.register
		end
	    
	    context 'drop event' do
	    	let(:message) { JSON.parse('{"timestamp":"1643721667956","layers":{"frame":{"frame_frame_encap_type":"25","frame_frame_time":"2022-02-01T13:21:07.958804000Z","frame_frame_offset_shift":"0.000000000","frame_frame_time_epoch":"1643721667.958804000","frame_frame_time_delta":"0.000000000","frame_frame_time_delta_displayed":"0.000000000","frame_frame_time_relative":"0.000000000","frame_frame_number":"1","frame_frame_len":"196","frame_frame_cap_len":"196","frame_frame_marked":false,"frame_frame_ignored":false,"frame_frame_protocols":"sll:ip:ospf"},"sll":{"sll_sll_pkttype":"0","sll_sll_hatype":"778","sll_sll_halen":"0","sll_sll_unused":"00:00:00:00:00:00:00:00","sll_sll_gretype":"0x00000800"},"ip":{"ip_ip_version":"4","ip_ip_hdr_len":"20","ip_ip_dsfield":"0x000000c0","ip_ip_dsfield_dscp":"48","ip_ip_dsfield_ecn":"0","ip_ip_len":"180","ip_ip_id":"0x00005f3e","ip_ip_flags":"0x00000000","ip_ip_flags_rb":false,"ip_ip_flags_df":false,"ip_ip_flags_mf":false,"ip_ip_frag_offset":"0","ip_ip_ttl":"1","ip_ip_proto":"89","ip_ip_checksum":"0x0000163b","ip_ip_checksum_status":"2","ip_ip_src":"177.177.177.1","ip_ip_addr":["177.177.177.1","224.0.0.5"],"ip_ip_src_host":"177.177.177.1","ip_ip_host":["177.177.177.1","224.0.0.5"],"ip_ip_dst":"224.0.0.5","ip_ip_dst_host":"224.0.0.5"},"ospf":{"ospf_ospf_header":null,"ospf_ospf_version":"2","ospf_ospf_msg":"4","ospf_ospf_msg_lsupdate":true,"ospf_ospf_packet_length":"160","ospf_ospf_srcrouter":"124.0.0.7","ospf_ospf_area_id":"0.0.0.8","ospf_ospf_checksum":"0x00006b5f","ospf_ospf_auth_type":"0","ospf_ospf_auth_none":"00:00:00:00:00:00:00:00","text":["LSA-type 1 (Router-LSA), len 132","Type: Stub     ID: 9.9.9.1         Data: 255.255.255.255 Metric: 1","Type: Stub     ID: 192.168.100.64  Data: 255.255.255.252 Metric: 10","Type: Stub     ID: 192.168.100.68  Data: 255.255.255.252 Metric: 10","Type: Stub     ID: 192.168.100.72  Data: 255.255.255.252 Metric: 10","Type: Stub     ID: 192.168.100.20  Data: 255.255.255.252 Metric: 10","Type: PTP      ID: 24.0.0.4        Data: 192.168.100.26  Metric: 65535","Type: Stub     ID: 192.168.100.24  Data: 255.255.255.252 Metric: 10","Type: PTP      ID: 124.0.0.7       Data: 192.168.100.78  Metric: 65535","Type: Stub     ID: 192.168.100.76  Data: 255.255.255.252 Metric: 10"],"ospf_ospf_ls_number_of_lsas":"0","ospf_ospf_lsa_age":"2","ospf_ospf_lsa_donotage":"0","ospf_ospf_v2_options":"0x00000028","ospf_ospf_v2_options_dn":false,"ospf_ospf_v2_options_o":false,"ospf_ospf_v2_options_dc":true,"ospf_ospf_v2_options_l":false,"ospf_ospf_v2_options_n":true,"ospf_ospf_v2_options_mc":false,"ospf_ospf_v2_options_e":false,"ospf_ospf_v2_options_mt":false,"ospf_ospf_lsa":"1","ospf_ospf_lsa_router":true,"ospf_ospf_lsa_id":"24.0.0.5","ospf_ospf_advrouter":"24.0.0.5","ospf_ospf_lsa_seqnum":"0x800004bf","ospf_ospf_lsa_chksum":"0x0000525c","ospf_ospf_lsa_length":"132","ospf_ospf_v2_router_lsa_flags":"0x00000002","ospf_ospf_v2_router_lsa_flags_h":false,"ospf_ospf_v2_router_lsa_flags_n":false,"ospf_ospf_v2_router_lsa_flags_w":false,"ospf_ospf_v2_router_lsa_flags_v":false,"ospf_ospf_v2_router_lsa_flags_e":true,"ospf_ospf_v2_router_lsa_flags_b":false,"ospf_ospf_lsa_number_of_links":"9","ospf_ospf_lsa_router_linkid":["9.9.9.1","192.168.100.64","192.168.100.68","192.168.100.72","192.168.100.20","24.0.0.4","192.168.100.24","124.0.0.7","192.168.100.76"],"ospf_ospf_lsa_router_linkdata":["255.255.255.255","255.255.255.252","255.255.255.252","255.255.255.252","255.255.255.252","192.168.100.26","255.255.255.252","192.168.100.78","255.255.255.252"],"ospf_ospf_lsa_router_linktype":["3","3","3","3","3","1","3","1","3"],"ospf_ospf_lsa_router_nummetrics":["0","0","0","0","0","0","0","0","0"],"ospf_ospf_lsa_router_metric0":["1","10","10","10","10","65535","10","65535","10"]}}}') }
	    	it "drop event if ospf_ospf_ls_number_of_lsas == 0" do
	    		subject.filter(event)
	    		expect(described_class).to eq(LogStash::Filters::Ospfpackets)
	    		expect(event).to be_cancelled
	    	end
        end
       
	    context 'drop event' do
	    	let(:message) { JSON.parse('{}') }
	    	it "drop event if ospf_ospf_ls_number_of_lsas == nil" do
	    		subject.filter(event)
	    		expect(described_class).to eq(LogStash::Filters::Ospfpackets)
	    		expect(event).to be_cancelled
	    	end
        end

	    context 'verify original event as received' do
	    	let(:message) { JSON.parse('{"timestamp":"1643723807633","layers":{"frame":{"frame_frame_encap_type":"25","frame_frame_time":"2022-02-01T13:56:47.633986000Z","frame_frame_offset_shift":"0.000000000","frame_frame_time_epoch":"1643723807.633986000","frame_frame_time_delta":"93.736344000","frame_frame_time_delta_displayed":"93.736344000","frame_frame_time_relative":"2139.675182000","frame_frame_number":"51","frame_frame_len":"100","frame_frame_cap_len":"100","frame_frame_marked":false,"frame_frame_ignored":false,"frame_frame_protocols":"sll:ip:ospf"},"sll":{"sll_sll_pkttype":"0","sll_sll_hatype":"778","sll_sll_halen":"0","sll_sll_unused":"00:00:00:00:00:00:00:00","sll_sll_gretype":"0x00000800"},"ip":{"ip_ip_version":"4","ip_ip_hdr_len":"20","ip_ip_dsfield":"0x000000c0","ip_ip_dsfield_dscp":"48","ip_ip_dsfield_ecn":"0","ip_ip_len":"84","ip_ip_id":"0x0000634c","ip_ip_flags":"0x00000000","ip_ip_flags_rb":false,"ip_ip_flags_df":false,"ip_ip_flags_mf":false,"ip_ip_frag_offset":"0","ip_ip_ttl":"1","ip_ip_proto":"89","ip_ip_checksum":"0x0000168f","ip_ip_checksum_status":"2","ip_ip_src":"175.175.175.1","ip_ip_addr":["175.175.175.1","224.0.0.5"],"ip_ip_src_host":"175.175.175.1","ip_ip_host":["175.175.175.1","224.0.0.5"],"ip_ip_dst":"224.0.0.5","ip_ip_dst_host":"224.0.0.5"},"ospf":{"ospf_ospf_header":null,"ospf_ospf_version":"2","ospf_ospf_msg":"4","ospf_ospf_msg_lsupdate":true,"ospf_ospf_packet_length":"64","ospf_ospf_srcrouter":"124.0.0.7","ospf_ospf_area_id":"0.0.0.0","ospf_ospf_checksum":"0x000050e2","ospf_ospf_auth_type":"0","ospf_ospf_auth_none":"00:00:00:00:00:00:00:00","text":"LSA-type 5 (AS-External-LSA (ASBR)), len 36","ospf_ospf_ls_number_of_lsas":"1","ospf_ospf_lsa_age":"2","ospf_ospf_lsa_donotage":"0","ospf_ospf_v2_options":"0x00000020","ospf_ospf_v2_options_dn":false,"ospf_ospf_v2_options_o":false,"ospf_ospf_v2_options_dc":true,"ospf_ospf_v2_options_l":false,"ospf_ospf_v2_options_n":false,"ospf_ospf_v2_options_mc":false,"ospf_ospf_v2_options_e":false,"ospf_ospf_v2_options_mt":false,"ospf_ospf_lsa":"5","ospf_ospf_lsa_asext":true,"ospf_ospf_lsa_id":"24.0.0.174","ospf_ospf_advrouter":"12.0.0.18","ospf_ospf_lsa_seqnum":"0x80000138","ospf_ospf_lsa_chksum":"0x0000f541","ospf_ospf_lsa_length":"36","ospf_ospf_lsa_asext_netmask":"255.255.255.255","ospf_ospf_lsa_asext_type":true,"ospf_ospf_lsa_tos":"0","ospf_ospf_metric":"20","ospf_ospf_lsa_asext_fwdaddr":"192.168.52.174","ospf_ospf_lsa_asext_extrttag":"0"}}}') }
	    	it "event equal to original" do
	    		events = [event]
	    		subject.filter(event) {|e| events << e }
	    		expect(events.length).to eq(2)
	    		expect(events[0]).to eq(event)
	    		expect(events[0].get("[json_parsed][layers][ospf][ospf_ospf_ls_number_of_lsas]")).to eq("1")
	    		# add more fields to test better
	    	end
        end

	    context 'verify fields removed in cloned message' do
	    	let(:message) { JSON.parse('{"timestamp":"1643723807633","layers":{"frame":{"frame_frame_encap_type":"25","frame_frame_time":"2022-02-01T13:56:47.633986000Z","frame_frame_offset_shift":"0.000000000","frame_frame_time_epoch":"1643723807.633986000","frame_frame_time_delta":"93.736344000","frame_frame_time_delta_displayed":"93.736344000","frame_frame_time_relative":"2139.675182000","frame_frame_number":"51","frame_frame_len":"100","frame_frame_cap_len":"100","frame_frame_marked":false,"frame_frame_ignored":false,"frame_frame_protocols":"sll:ip:ospf"},"sll":{"sll_sll_pkttype":"0","sll_sll_hatype":"778","sll_sll_halen":"0","sll_sll_unused":"00:00:00:00:00:00:00:00","sll_sll_gretype":"0x00000800"},"ip":{"ip_ip_version":"4","ip_ip_hdr_len":"20","ip_ip_dsfield":"0x000000c0","ip_ip_dsfield_dscp":"48","ip_ip_dsfield_ecn":"0","ip_ip_len":"84","ip_ip_id":"0x0000634c","ip_ip_flags":"0x00000000","ip_ip_flags_rb":false,"ip_ip_flags_df":false,"ip_ip_flags_mf":false,"ip_ip_frag_offset":"0","ip_ip_ttl":"1","ip_ip_proto":"89","ip_ip_checksum":"0x0000168f","ip_ip_checksum_status":"2","ip_ip_src":"175.175.175.1","ip_ip_addr":["175.175.175.1","224.0.0.5"],"ip_ip_src_host":"175.175.175.1","ip_ip_host":["175.175.175.1","224.0.0.5"],"ip_ip_dst":"224.0.0.5","ip_ip_dst_host":"224.0.0.5"},"ospf":{"ospf_ospf_header":null,"ospf_ospf_version":"2","ospf_ospf_msg":"4","ospf_ospf_msg_lsupdate":true,"ospf_ospf_packet_length":"64","ospf_ospf_srcrouter":"124.0.0.7","ospf_ospf_area_id":"0.0.0.0","ospf_ospf_checksum":"0x000050e2","ospf_ospf_auth_type":"0","ospf_ospf_auth_none":"00:00:00:00:00:00:00:00","text":"LSA-type 5 (AS-External-LSA (ASBR)), len 36","ospf_ospf_ls_number_of_lsas":"1","ospf_ospf_lsa_age":"2","ospf_ospf_lsa_donotage":"0","ospf_ospf_v2_options":"0x00000020","ospf_ospf_v2_options_dn":false,"ospf_ospf_v2_options_o":false,"ospf_ospf_v2_options_dc":true,"ospf_ospf_v2_options_l":false,"ospf_ospf_v2_options_n":false,"ospf_ospf_v2_options_mc":false,"ospf_ospf_v2_options_e":false,"ospf_ospf_v2_options_mt":false,"ospf_ospf_lsa":"5","ospf_ospf_lsa_asext":true,"ospf_ospf_lsa_id":"24.0.0.174","ospf_ospf_advrouter":"12.0.0.18","ospf_ospf_lsa_seqnum":"0x80000138","ospf_ospf_lsa_chksum":"0x0000f541","ospf_ospf_lsa_length":"36","ospf_ospf_lsa_asext_netmask":"255.255.255.255","ospf_ospf_lsa_asext_type":true,"ospf_ospf_lsa_tos":"0","ospf_ospf_metric":"20","ospf_ospf_lsa_asext_fwdaddr":"192.168.52.174","ospf_ospf_lsa_asext_extrttag":"0"}}}') }
	    	it "no more specific fields in cloned event" do
	            events = [event]
                subject.filter(event) {|e| events << e }
                expect(events.length).to eq(2)
	    		expect(events[1].get("[json_parsed][layers][sll]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ip]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][frame]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_header]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_version]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_msg]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_msg_lsupdate]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_packet_length]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_checksum]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_auth_type]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_auth_none]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][text]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_ls_number_of_lsas]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_o]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_dc]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_l]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_n]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_mc]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_mt]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_summary]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_chksum]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_length]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_router]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_tos]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_asext]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_nssa]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_opaque]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_router_lsa_flags]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_router_lsa_flags_h]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_router_lsa_flags_n]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_router_lsa_flags_w]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_router_lsa_flags_v]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_router_lsa_flags_e]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_router_lsa_flags_b]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_router_nummetrics]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsid_te_lsa_reserved]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsid_te_lsa_instance]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_tlv_type]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_tlv_length]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_mpls_remote_addr]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_mpls_link_max_bw]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_mpls_pri]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_ls_number_of_lsas]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_dn]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_e]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_donotage]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_asext_fwdaddr]")).to eq(nil)
	    		expect(events[1].get("[json_parsed][layers][ospf][ospf_ospf_lsa_asext_extrttag]")).to eq(nil)
	    	end
        end
              	    
	    context 'SINGLE LSA TYPE 5' do
	    	let(:message) { JSON.parse('{"timestamp":"1643723807633","layers":{"frame":{"frame_frame_encap_type":"25","frame_frame_time":"2022-02-01T13:56:47.633986000Z","frame_frame_offset_shift":"0.000000000","frame_frame_time_epoch":"1643723807.633986000","frame_frame_time_delta":"93.736344000","frame_frame_time_delta_displayed":"93.736344000","frame_frame_time_relative":"2139.675182000","frame_frame_number":"51","frame_frame_len":"100","frame_frame_cap_len":"100","frame_frame_marked":false,"frame_frame_ignored":false,"frame_frame_protocols":"sll:ip:ospf"},"sll":{"sll_sll_pkttype":"0","sll_sll_hatype":"778","sll_sll_halen":"0","sll_sll_unused":"00:00:00:00:00:00:00:00","sll_sll_gretype":"0x00000800"},"ip":{"ip_ip_version":"4","ip_ip_hdr_len":"20","ip_ip_dsfield":"0x000000c0","ip_ip_dsfield_dscp":"48","ip_ip_dsfield_ecn":"0","ip_ip_len":"84","ip_ip_id":"0x0000634c","ip_ip_flags":"0x00000000","ip_ip_flags_rb":false,"ip_ip_flags_df":false,"ip_ip_flags_mf":false,"ip_ip_frag_offset":"0","ip_ip_ttl":"1","ip_ip_proto":"89","ip_ip_checksum":"0x0000168f","ip_ip_checksum_status":"2","ip_ip_src":"175.175.175.1","ip_ip_addr":["175.175.175.1","224.0.0.5"],"ip_ip_src_host":"175.175.175.1","ip_ip_host":["175.175.175.1","224.0.0.5"],"ip_ip_dst":"224.0.0.5","ip_ip_dst_host":"224.0.0.5"},"ospf":{"ospf_ospf_header":null,"ospf_ospf_version":"2","ospf_ospf_msg":"4","ospf_ospf_msg_lsupdate":true,"ospf_ospf_packet_length":"64","ospf_ospf_srcrouter":"124.0.0.7","ospf_ospf_area_id":"0.0.0.8","ospf_ospf_checksum":"0x000050e2","ospf_ospf_auth_type":"0","ospf_ospf_auth_none":"00:00:00:00:00:00:00:00","text":"LSA-type 5 (AS-External-LSA (ASBR)), len 36","ospf_ospf_ls_number_of_lsas":"1","ospf_ospf_lsa_age":"2","ospf_ospf_lsa_donotage":"0","ospf_ospf_v2_options":"0x00000020","ospf_ospf_v2_options_dn":false,"ospf_ospf_v2_options_o":false,"ospf_ospf_v2_options_dc":true,"ospf_ospf_v2_options_l":false,"ospf_ospf_v2_options_n":false,"ospf_ospf_v2_options_mc":false,"ospf_ospf_v2_options_e":false,"ospf_ospf_v2_options_mt":false,"ospf_ospf_lsa":"5","ospf_ospf_lsa_asext":true,"ospf_ospf_lsa_id":"24.0.0.174","ospf_ospf_advrouter":"12.0.0.18","ospf_ospf_lsa_seqnum":"0x80000138","ospf_ospf_lsa_chksum":"0x0000f541","ospf_ospf_lsa_length":"36","ospf_ospf_lsa_asext_netmask":"255.255.255.255","ospf_ospf_lsa_asext_type":true,"ospf_ospf_lsa_tos":"0","ospf_ospf_metric":"20","ospf_ospf_lsa_asext_fwdaddr":"192.168.52.174","ospf_ospf_lsa_asext_extrttag":"0"}}}') }
	    	it "clone 1 event type 5" do
	            events = [event]
                subject.filter(event) {|e| events << e }
                expect(events.length).to eq(2)
	    		expect(events[1].get("[ospf][timestamp]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time_epoch]"))
	    		expect(events[1].get("[ospf][lsa_type]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa]"))
	    		expect(events[1].get("[ospf][lsa_age]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_age]"))
	    		expect(events[1].get("[ospf][lsa_seqnum]")).to eq(2147483960)
	    		expect(events[1].get("[ospf][lsu_pointer]")).to eq("1643723807.633986000-8-124.0.0.7")
	    		expect(events[1].get("[ospf][adv_router]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_advrouter]"))
	    		expect(events[1].get("[ospf][prefix-id]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_id]"))
	    		expect(events[1].get("[ospf][link-id]")).to eq(nil)
	    		expect(events[1].get("[ospf][netmask]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_asext_netmask]"))
	    		expect(events[1].get("[ospf][link_type]")).to eq(nil)
	    		expect(events[1].get("[ospf][ospf_metric]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_metric]"))
	    		expect(events[1].get("[ospf][prefix_ip_fwdaddr]")).to eq(nil)
	    		expect(events[1].get("[ospf][ospf_external_tag]")).to eq(nil)
	    		expect(events[1].get("[ospf][lsa_down_bit]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_dn]"))
	    		expect(events[1].get("[ospf][lsa_external_bit]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_e]"))
	    		expect(events[1].get("[ospf][lsa_propagate_bit]")).to eq(nil)
	    		expect(events[1].get("[ospf][lsa_opaque_type]")).to eq(nil)
	    		expect(events[1].get("[ospf][te_metric]")).to eq(nil)
	    		expect(events[1].get("[ospf][mpls_linkcolor]")).to eq(nil)
	    		expect(events[1].get("[ospf][metric_type]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_asext_type]"))
	    		expect(events[1].get("[ospf][extra]")).to eq("")
	    		expect(events[1].get("[ospf][area_id]")).to eq(8)
	    		expect(events[1].get("[ospf][utc_time]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time]"))
	    		expect(events[1].get("[ospf][timestamp]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time_epoch]"))
	    		
	    	end
        end
       
	    context 'SINGLE LSA TYPE 3' do
	    	let(:message) { JSON.parse('{"timestamp":"1643722500612","layers":{"frame":{"frame_frame_encap_type":"25","frame_frame_time":"2022-02-01T13:35:00.612803000Z","frame_frame_offset_shift":"0.000000000","frame_frame_time_epoch":"1643722500.612803000","frame_frame_time_delta":"0.001447000","frame_frame_time_delta_displayed":"0.001447000","frame_frame_time_relative":"832.653999000","frame_frame_number":"17","frame_frame_len":"92","frame_frame_cap_len":"92","frame_frame_marked":false,"frame_frame_ignored":false,"frame_frame_protocols":"sll:ip:ospf"},"sll":{"sll_sll_pkttype":"0","sll_sll_hatype":"778","sll_sll_halen":"0","sll_sll_unused":"00:00:00:00:00:00:00:00","sll_sll_gretype":"0x00000800"},"ip":{"ip_ip_version":"4","ip_ip_hdr_len":"20","ip_ip_dsfield":"0x000000c0","ip_ip_dsfield_dscp":"48","ip_ip_dsfield_ecn":"0","ip_ip_len":"76","ip_ip_id":"0x00006077","ip_ip_flags":"0x00000000","ip_ip_flags_rb":false,"ip_ip_flags_df":false,"ip_ip_flags_mf":false,"ip_ip_frag_offset":"0","ip_ip_ttl":"1","ip_ip_proto":"89","ip_ip_checksum":"0x0000196c","ip_ip_checksum_status":"2","ip_ip_src":"175.175.175.1","ip_ip_addr":["175.175.175.1","224.0.0.5"],"ip_ip_src_host":"175.175.175.1","ip_ip_host":["175.175.175.1","224.0.0.5"],"ip_ip_dst":"224.0.0.5","ip_ip_dst_host":"224.0.0.5"},"ospf":{"ospf_ospf_header":null,"ospf_ospf_version":"2","ospf_ospf_msg":"4","ospf_ospf_msg_lsupdate":true,"ospf_ospf_packet_length":"56","ospf_ospf_srcrouter":"124.0.0.7","ospf_ospf_area_id":"0.0.0.0","ospf_ospf_checksum":"0x000061da","ospf_ospf_auth_type":"0","ospf_ospf_auth_none":"00:00:00:00:00:00:00:00","text":"LSA-type 3 (Summary-LSA (IP network)), len 28","ospf_ospf_ls_number_of_lsas":"1","ospf_ospf_lsa_age":"1","ospf_ospf_lsa_donotage":"0","ospf_ospf_v2_options":"0x00000022","ospf_ospf_v2_options_dn":false,"ospf_ospf_v2_options_o":false,"ospf_ospf_v2_options_dc":true,"ospf_ospf_v2_options_l":false,"ospf_ospf_v2_options_n":false,"ospf_ospf_v2_options_mc":false,"ospf_ospf_v2_options_e":true,"ospf_ospf_v2_options_mt":false,"ospf_ospf_lsa":"3","ospf_ospf_lsa_summary":true,"ospf_ospf_lsa_id":"177.177.177.0","ospf_ospf_advrouter":"124.0.0.7","ospf_ospf_lsa_seqnum":"0x800000a9","ospf_ospf_lsa_chksum":"0x00009e60","ospf_ospf_lsa_length":"28","ospf_ospf_lsa_asbr_netmask":"255.255.255.252","ospf_ospf_lsa_tos":"0","ospf_ospf_metric":"65535"}}}') }
	    	it "clone 1 event type 3" do
	            events = [event]
                subject.filter(event) {|e| events << e }
                expect(events.length).to eq(2)
	    		expect(events[1].get("[ospf][timestamp]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time_epoch]"))
	    		expect(events[1].get("[ospf][lsa_type]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa]"))
	    		expect(events[1].get("[ospf][lsa_age]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_age]"))
	    		expect(events[1].get("[ospf][lsa_seqnum]")).to eq(2147483817)
	    		expect(events[1].get("[ospf][lsu_pointer]")).to eq("1643722500.612803000-0-124.0.0.7")
	    		expect(events[1].get("[ospf][adv_router]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_advrouter]"))
	    		expect(events[1].get("[ospf][prefix-id]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_id]"))
	    		expect(events[1].get("[ospf][link-id]")).to eq(nil)
	    		expect(events[1].get("[ospf][netmask]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_lsa_asbr_netmask]"))
	    		expect(events[1].get("[ospf][link_type]")).to eq(nil)
	    		expect(events[1].get("[ospf][ospf_metric]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_metric]"))
	    		expect(events[1].get("[ospf][prefix_ip_fwdaddr]")).to eq(nil)
	    		expect(events[1].get("[ospf][ospf_external_tag]")).to eq(nil)
	    		expect(events[1].get("[ospf][lsa_down_bit]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_dn]"))
	    		expect(events[1].get("[ospf][lsa_external_bit]")).to eq(events[0].get("[json_parsed][layers][ospf][ospf_ospf_v2_options_e]"))
	    		expect(events[1].get("[ospf][lsa_propagate_bit]")).to eq(nil)
	    		expect(events[1].get("[ospf][lsa_opaque_type]")).to eq(nil)
	    		expect(events[1].get("[ospf][te_metric]")).to eq(nil)
	    		expect(events[1].get("[ospf][mpls_linkcolor]")).to eq(nil)
	    		expect(events[1].get("[ospf][metric_type]")).to eq(nil)
	    		expect(events[1].get("[ospf][extra]")).to eq("")
	    		expect(events[1].get("[ospf][area_id]")).to eq(0)
	    		expect(events[1].get("[ospf][utc_time]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time]"))
	    		expect(events[1].get("[ospf][timestamp]")).to eq(events[0].get("[json_parsed][layers][frame][frame_frame_time_epoch]"))
	    	end
        end

	    context 'FIVE LSA TYPE 3' do
	    	let(:message) { JSON.parse('{"timestamp":"1643722500713","layers":{"frame":{"frame_frame_encap_type":"25","frame_frame_time":"2022-02-01T13:35:00.713025000Z","frame_frame_offset_shift":"0.000000000","frame_frame_time_epoch":"1643722500.713025000","frame_frame_time_delta":"0.001653000","frame_frame_time_delta_displayed":"0.001653000","frame_frame_time_relative":"832.754221000","frame_frame_number":"23","frame_frame_len":"204","frame_frame_cap_len":"204","frame_frame_marked":false,"frame_frame_ignored":false,"frame_frame_protocols":"sll:ip:ospf"},"sll":{"sll_sll_pkttype":"0","sll_sll_hatype":"778","sll_sll_halen":"0","sll_sll_unused":"00:00:00:00:00:00:00:00","sll_sll_gretype":"0x00000800"},"ip":{"ip_ip_version":"4","ip_ip_hdr_len":"20","ip_ip_dsfield":"0x000000c0","ip_ip_dsfield_dscp":"48","ip_ip_dsfield_ecn":"0","ip_ip_len":"188","ip_ip_id":"0x00006081","ip_ip_flags":"0x00000000","ip_ip_flags_rb":false,"ip_ip_flags_df":false,"ip_ip_flags_mf":false,"ip_ip_frag_offset":"0","ip_ip_ttl":"1","ip_ip_proto":"89","ip_ip_checksum":"0x000014f0","ip_ip_checksum_status":"2","ip_ip_src":"177.177.177.1","ip_ip_addr":["177.177.177.1","224.0.0.5"],"ip_ip_src_host":"177.177.177.1","ip_ip_host":["177.177.177.1","224.0.0.5"],"ip_ip_dst":"224.0.0.5","ip_ip_dst_host":"224.0.0.5"},"ospf":{"ospf_ospf_header":null,"ospf_ospf_version":"2","ospf_ospf_msg":"4","ospf_ospf_msg_lsupdate":true,"ospf_ospf_packet_length":"168","ospf_ospf_srcrouter":"124.0.0.7","ospf_ospf_area_id":"0.0.0.8","ospf_ospf_checksum":"0x00008536","ospf_ospf_auth_type":"0","ospf_ospf_auth_none":"00:00:00:00:00:00:00:00","text":["LSA-type 3 (Summary-LSA (IP network)), len 28","LSA-type 3 (Summary-LSA (IP network)), len 28","LSA-type 3 (Summary-LSA (IP network)), len 28","LSA-type 3 (Summary-LSA (IP network)), len 28","LSA-type 3 (Summary-LSA (IP network)), len 28"],"ospf_ospf_ls_number_of_lsas":"5","ospf_ospf_lsa_age":["1","1","1","1","1"],"ospf_ospf_lsa_donotage":["0","0","0","0","0"],"ospf_ospf_v2_options":["0x00000028","0x00000028","0x00000028","0x00000028","0x00000028"],"ospf_ospf_v2_options_dn":[false,false,false,false,false],"ospf_ospf_v2_options_o":[false,false,false,false,false],"ospf_ospf_v2_options_dc":[true,true,true,true,true],"ospf_ospf_v2_options_l":[false,false,false,false,false],"ospf_ospf_v2_options_n":[true,true,true,true,true],"ospf_ospf_v2_options_mc":[false,false,false,false,false],"ospf_ospf_v2_options_e":[false,false,false,false,false],"ospf_ospf_v2_options_mt":[false,false,false,false,false],"ospf_ospf_lsa":["3","3","3","3","3"],"ospf_ospf_lsa_summary":[true,true,true,true,true],"ospf_ospf_lsa_id":["12.0.0.5","172.16.12.5","172.16.30.5","172.16.40.5","172.17.12.5"],"ospf_ospf_advrouter":["124.0.0.7","124.0.0.7","124.0.0.7","124.0.0.7","124.0.0.7"],"ospf_ospf_lsa_seqnum":["0x800000d6","0x800000d6","0x800000d6","0x800000d6","0x800000d6"],"ospf_ospf_lsa_chksum":["0x0000614c","0x0000f3fc","0x00002db1","0x0000be16","0x0000e708"],"ospf_ospf_lsa_length":["28","28","28","28","28"],"ospf_ospf_lsa_asbr_netmask":["255.255.255.255","255.255.255.255","255.255.255.255","255.255.255.255","255.255.255.255"],"ospf_ospf_lsa_tos":["0","0","0","0","0"],"ospf_ospf_metric":["31","31","31","31","31"]}}}') }
	    	it "clone 1 event type 3" do
	            events = [event]
                subject.filter(event) {|e| events << e }
                expect(events.length).to eq(6)
                (1..events.length-1).each do |n|
				    check_type_3(events, n, n-1)
				end    		
	    	end
        end
       
    end
end
