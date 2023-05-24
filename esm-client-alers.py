#!/usr/bin/python3.5

import re
import urllib.parse
import ipaddress
from collections import defaultdict
  # This script is meant for logging an IP within a timeframe of 12 hours.
            # If within 12 hours there are 500 or more attempts to visit or download a specified page(example: test.com/conf/). 
            # An alert will be generated with json format(msg = { ) and sent to the syslog where it has to be parsed to a useful event


def exweb(tf_list, save_to, varstr):
    fh = open(varstr, "r")
    json_conf = json.loads(fh.read())
    fh.close()
    all_events = list()
    for tf_window in tf_list:
        (tf_start, tf_end) = tf_window.split("|")
        events = EventManager(
            time_range="CUSTOM",
            start_time=tf_start,
            end_time=tf_end,
            fields=[ "DSIDSigID", "FirstTime", "LastTime", "SrcIP", "Alert.4259841", "HostID", "URL", "EventCount", "Rule.msg",], 
            filters=[
                FieldFilter("IPSID", devices, operator="IN"),
               FieldFilter("HostID", "test.nl", "CONTAINS"),
                FieldFilter("Rule.msg", "ApplicationGatewayFirewall -", "CONTAINS")
                # FieldFilter("URL", "/conf", "EQUALS")
            ],
            limit=num_rows
        )
        events.load_data()
        all_events += events
    start_dt = datetime.datetime.strptime(tf_list[0].split("|")[0], "%Y-%m-%dT%H:%M:%S.000Z")
    end_dt = datetime.datetime.strptime(tf_list[-1].split("|")[1], "%Y-%m-%dT%H:%M:%S.000Z")
    timeframe_checked = int((end_dt-start_dt).total_seconds()//60)
    # sig_name = "ApplicationGatewayAccess - "
    sig_name = "ApplicationGatewayFirewall - "
    sig_except = "ApplicationGatewayFirewall - Missing User Agent Header"
    sig_except2 = "ApplicationGatewayFirewall - Request Missing an Accept Header"
    time_window = 12 * 60 * 60 # in seconden
    now = datetime.datetime.now()
    w_counter = defaultdict(int)
    
    
    for e in all_events:
        rule_msg = e["Rule.msg"]
        src_ip = e["Alert.SrcIP"]
        if (now - end_dt).total_seconds() <= time_window:
            if sig_name in e["Rule.msg"] and (sig_except not in e["Rule.msg"] and sig_except2 not in e["Rule.msg"]):        
                if src_ip not in w_counter.keys():
                    w_counter[src_ip] = 0
                else:
                    w_counter[src_ip] += int(e["EventCount"])


    for source_i,exploit_count in w_counter.items(): 
        if w_counter[source_i] >= 500:
            print(w_counter[source_i])
            print(f'Sending SYSLOG for {source_i}: Possible Web exploitation attempt.')
            msg = {
                "First time"        : tf_start,
                "Last time"         : tf_end,
                "Device"            : device_id_to_name[devices[0]].upper(),
                "Title"             : "Possible Web exploitation attempt",
                "Source_ip"         : source_i,
                "Eventcount"        : exploit_count,
                "detection_ts"      : datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
                "timeframe_checked" : timeframe_checked
            }
            send_syslog(json.dumps(msg), json_conf)
            print(msg)
            
           
        
