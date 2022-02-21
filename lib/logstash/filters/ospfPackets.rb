# encoding: utf-8
require "logstash/filters/base"

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Ospfpackets < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  # }
  #
  config_name "ospfPackets"

  public
  def register
    # Add instance variables
  end # def register

  public
  def filter(event)
    logger.info("EVENT", "value" => event.get("[json_parsed]"))
#     puts "event: "
#     puts event.get("[json_parsed]")
#     event.to_hash.each { |k, v| 
#     	puts k
#     	puts v
#     }
   
    # get total lsa packets in single lsa update
    ospf_ospf_ls_number_of_lsas = event.get("[json_parsed][layers][ospf][ospf_ospf_ls_number_of_lsas]")
    
    if hasNoPackets(ospf_ospf_ls_number_of_lsas)
    	event.cancel
        return
    end

    # Create an Array of events, original + cloned    
    events = Array.new()
    
    # Add always the input event, then split event in multiple events
    events.push(event)

    # set a Hash with all fields from original event
	fields = setArrayFieldsFromEvent(event, ospf_ospf_ls_number_of_lsas)
    logger.info("fields", "value" => fields)
    filter_matched(event)

    # initialize specific index for each field
    ospf_ospf_lsa_id_index = 0
	ospf_ospf_lsid_opaque_type = 0
	ospf_ospf_metric_index = 0
	ospf_ospf_v2_options_dn_index = 0
	ospf_ospf_v2_options_e_index = 0
	ospf_ospf_lsa_asext_netmask_index = 0
	ospf_ospf_lsa_asext_type_index = 0
	index_type_10 = 0
	index_type_3 = 0
    
    fields["ospf_ospf_lsa"].each_with_index do |lsa_type,lsa_index|
      
        cloned_event = event.clone
      
        renameCommonFields(cloned_event, event)
      
        # concat frame_frame_time_epoch-ospf_ospf_area_id-ospf_ospf_srcrouter
        lsu_pointer = sprintf("%s-%s-%s", event.get("[json_parsed][layers][frame][frame_frame_time_epoch]"),cloned_event.get("[ospf][area_id]"),event.get("[json_parsed][layers][ospf][ospf_ospf_srcrouter]"))
        cloned_event.set("[ospf][lsu_pointer]", lsu_pointer)
        
        renameSpecificField(cloned_event, "[ospf][lsa_age]", "[json_parsed][layers][ospf][ospf_ospf_lsa_age]",  fields["ospf_ospf_lsa_age"][lsa_index.to_i])
        renameSpecificField(cloned_event, "[ospf][lsa_type]", "[json_parsed][layers][ospf][ospf_ospf_lsa]",  fields["ospf_ospf_lsa"][lsa_index.to_i])
        renameSpecificField(cloned_event, "[ospf][lsa_seqnum]", "[json_parsed][layers][ospf][ospf_ospf_lsa_seqnum]",  fields["ospf_ospf_lsa_seqnum"][lsa_index.to_i].to_i(16))
        
        setDefaultValues(cloned_event)

		# handling field ospf_ospf_advrouter
		if ["1","3","5","7"].include?(lsa_type)
			cloned_event.set("[ospf][adv_router]", fields["ospf_ospf_advrouter"][lsa_index.to_i])
		end

		# handling field prefix-id
		if ["1","3","5","7","10"].include?(lsa_type)
			if ["3","5","7"].include?(lsa_type)
			  cloned_event.set("[ospf][prefix-id]", fields["ospf_ospf_lsa_id"][ospf_ospf_lsa_id_index])
			elsif lsa_type == "10"
			  cloned_event.set("[ospf][prefix-id]", fields["ospf_ospf_mpls_local_addr"][index_type_10])
			elsif lsa_type == "1"
			end
		    # incremented for all lsa_types
		    ospf_ospf_lsa_id_index += 1
		end

		# handling field ospf_ospf_lsa_asbr_netmask
		if ["3"].include?(lsa_type)
			cloned_event.set("[ospf][netmask]", fields["ospf_ospf_lsa_asbr_netmask"][index_type_3])
		end
	
		# handling field ospf_ospf_metric
		if ["3","5","7"].include?(lsa_type)
			cloned_event.set("[ospf][ospf_metric]", fields["ospf_ospf_metric"][ospf_ospf_metric_index])
			ospf_ospf_metric_index += 1
		end
	
		# handling field ospf_ospf_v2_options_dn
		if ["3","5","7"].include?(lsa_type)
			cloned_event.set("[ospf][lsa_down_bit]", fields["ospf_ospf_v2_options_dn"][ospf_ospf_v2_options_dn_index])
			ospf_ospf_v2_options_dn_index += 1
		end
	
		# handling field ospf_ospf_v2_options_e
		if ["1","3","5","7"].include?(lsa_type)
			cloned_event.set("[ospf][lsa_external_bit]", fields["ospf_ospf_v2_options_e"][ospf_ospf_v2_options_e_index])
			ospf_ospf_v2_options_e_index += 1
		end
	
		# handling field ospf_ospf_lsa_asext_netmask
		if ["5","7"].include?(lsa_type)
			cloned_event.set("[ospf][netmask]", fields["ospf_ospf_lsa_asext_netmask"][ospf_ospf_lsa_asext_netmask_index])
			ospf_ospf_lsa_asext_netmask_index += 1
		end
	
		# handling field ospf_ospf_lsa_asext_netmask
		if ["5","7"].include?(lsa_type)
			cloned_event.set("[ospf][metric_type]", fields["ospf_ospf_lsa_asext_type"][ospf_ospf_lsa_asext_type_index])
			ospf_ospf_lsa_asext_type_index += 1
		end

        if lsa_type == "1"

            # LSA TYPE 1 must be cloned for each link
            lsa_type1_link_index = 0
            ospf_ospf_lsa_number_of_links = ospf_ospf_ls_number_of_lsas == "1" ? event.get("[json_parsed][layers][ospf][ospf_ospf_lsa_number_of_links]").split : event.get("[json_parsed][layers][ospf][ospf_ospf_lsa_number_of_links]")
            
            logger.info("ospf_ospf_lsa_number_of_links_group:", "value" => ospf_ospf_lsa_number_of_links.length)
            ospf_ospf_lsa_number_of_links.each_with_index do |lsa_link_group, lsa_link_group_index|
            	
          		logger.info("ospf_ospf_lsa_number_of_links:", "value" => lsa_link_group)
          		(1..lsa_link_group.to_i).each do |n|
          			link_index = n - 1
              		logger.info("link:", "value" => link_index)
#        		        ospf_ospf_lsa_router_linkid = lsa_link_group == "1" ? event.get("[json_parsed][layers][ospf][ospf_ospf_lsa_router_linkid]").split : event.get("[json_parsed][layers][ospf][ospf_ospf_lsa_router_linkid]")

	                # clone from cloned_event, not from original event
	                cloned_event_type1 = cloned_event.clone()
	
	                lsa_type1_link_index = lsa_type1_link_index + 1
	              
	            end
	           
			end
		
        elsif lsa_type == "2"

            # events.push(cloned_event)

        elsif lsa_type == "3"

            events.push(cloned_event)
            
            index_type_3 += 1

        elsif lsa_type == "4"

            # events.push(cloned_event)

        elsif lsa_type == "5"

            events.push(cloned_event)
            
        elsif lsa_type == "7"

            # events.push(cloned_event)    

        elsif lsa_type == "9"

            # events.push(cloned_event)

        elsif lsa_type == "10"

            # events.push(cloned_event)
            
            index_type_10 += 1

        elsif lsa_type == "11"

            # events.push(cloned_event)

        else
            logger.info("TYPE UNKNOWN")
        end

        # remove fields because mapped into other fields
        removeUnusedFieldsAfterUsing(cloned_event)
        
    end
    
    logger.info("numero eventi generati:", "value" => events.length)

    events.each do |r_event|
      # If the user has generated a new event we yield that for them here
      if event != r_event
        yield r_event
      else
      	logger.info("original event parsed")
      end
      r_event
    end
  end # def filter

  def close
  end
  
  private

  def hasNoPackets(ospf_ospf_ls_number_of_lsas)
  	logger.info("ospf_ospf_ls_number_of_lsas:", "value" => ospf_ospf_ls_number_of_lsas)
    if ["0", nil].include? ospf_ospf_ls_number_of_lsas
        logger.info("no lsa, drop message")
        return true
    end
    return false
  end
 
  def renameCommonFields(cloned_event, event)
    cloned_event.set("[ospf][timestamp]" , event.get("[json_parsed][layers][frame][frame_frame_time_epoch]"))
	cloned_event.remove("[json_parsed][layers][frame][frame_frame_time_epoch]")
	
	cloned_event.set("[ospf][utc_time]" , event.get("[json_parsed][layers][frame][frame_frame_time]"))
	cloned_event.remove("[json_parsed][layers][frame][frame_frame_time]")
	
	# ip address: x.y.z.t => area_id = (x * 16.777.216 + y * 65536 + z * 256 + t) 
	area_id = event.get("[json_parsed][layers][ospf][ospf_ospf_area_id]").split(".").map { |i| i.to_i }.reverse.inject([]) { |memo,part| memo << part * (256 ** memo.size) }.inject(0) { |memo, part|memo += part }
	cloned_event.set("[ospf][area_id]" , area_id)
	cloned_event.remove("[json_parsed][layers][ospf][ospf_ospf_area_id]")
  end

  def setDefaultValues(cloned_event)
    cloned_event.set("[ospf][metric_type]", nil)
    cloned_event.set("[ospf][adv_router]", nil)
    cloned_event.set("[ospf][prefix-id]", nil)
    cloned_event.set("[ospf][link-id]", nil)
    cloned_event.set("[ospf][netmask]", nil)
    cloned_event.set("[ospf][link_type]", nil)
    cloned_event.set("[ospf][ospf_metric]", nil)
    cloned_event.set("[ospf][prefix_ip_fwdaddr]", nil)
    cloned_event.set("[ospf][ospf_external_tag]", nil)
    cloned_event.set("[ospf][lsa_down_bit]", nil)
    cloned_event.set("[ospf][lsa_external_bit]", nil)
    cloned_event.set("[ospf][lsa_propagate_bit]", nil)
    cloned_event.set("[ospf][lsa_opaque_type]", nil)
    cloned_event.set("[ospf][te_metric]", nil)
    cloned_event.set("[ospf][mpls_linkcolor]", nil)
    cloned_event.set("[ospf][extra]", "")
  end
 
  def getArrayFromEvent(event, ospf_ospf_ls_number_of_lsas, key)
    # mutate fields in array if they are not an array, for example if number_of_lsas == 1
    array_event = nil
    value = event.get(key)
    if value != nil
      if [true, false].include? value
  	  	# boolean single value
  	  	array_event = [value]
  	  else
  	  	array_event = ospf_ospf_ls_number_of_lsas == "1" ? value.split : value
  	  end
  	end
  	return array_event
  end
 
  def setArrayFieldsFromEvent(event, ospf_ospf_ls_number_of_lsas)
    fields = Hash.new()
    fields["ospf_ospf_lsa"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa]")
    fields["ospf_ospf_lsa_age"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_age]")
	fields["ospf_ospf_lsa_seqnum"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_seqnum]")
    fields["ospf_ospf_advrouter"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_advrouter]")
    fields["ospf_ospf_lsa_router_linkid"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_router_linkid]")
    fields["ospf_ospf_lsa_router_linkdata"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_router_linkdata]")
    fields["ospf_ospf_lsa_router_linktype"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_router_linktype]")
    fields["ospf_ospf_lsa_router_metric0"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_router_metric0]")
    fields["ospf_ospf_lsa_id"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_id]")
    fields["ospf_ospf_lsa_asbr_netmask"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_asbr_netmask]")
    fields["ospf_ospf_metric"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_metric]")
    fields["ospf_ospf_lsa_asext_netmask"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_asext_netmask]")
    fields["ospf_ospf_lsa_asext_type"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_asext_type]")
    fields["ospf_ospf_lsa_asext_fwdaddr"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_asext_fwdaddr]")
    fields["ospf_ospf_lsa_asext_extrttag"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsa_asext_extrttag]")
    fields["ospf_ospf_v2_options_dn"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_v2_options_dn]")
    fields["ospf_ospf_v2_options_e"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_v2_options_e]")
    fields["ospf_ospf_v2_options_p"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_v2_options_p]")
    fields["ospf_ospf_lsid_opaque_type"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_lsid_opaque_type]")
    fields["ospf_ospf_mpls_routerid"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_mpls_routerid]")
    fields["ospf_ospf_mpls_linktype"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_mpls_linktype]")
    fields["ospf_ospf_mpls_linkid"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_mpls_linkid]")
    fields["ospf_ospf_mpls_local_addr"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_mpls_local_addr]")
    fields["ospf_ospf_mpls_te_metric"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_mpls_te_metric]")
    fields["ospf_ospf_mpls_linkcolor"] = getArrayFromEvent(event,ospf_ospf_ls_number_of_lsas,"[json_parsed][layers][ospf][ospf_ospf_mpls_linkcolor]")
    return fields
  end
 
  def renameSpecificField(cloned_event, new_key, old_key,  value)
    cloned_event.set(new_key , value)
    cloned_event.remove(old_key)
  end
 
  def removeUnusedFieldsAfterUsing(cloned_event)
    cloned_event.remove("[json_parsed]")
  end
 
end # class LogStash::Filters::Ospfpackets
