/* Detector-- Function: accepts Vec of FailedLogin structs, groups them by IP addr
and checks groups against threshold and window 
groups of events that meet threshold and window create and return alerts */


use chrono::{Duration, NaiveDateTime};
use std::net::IpAddr;
use std::collections::HashMap;
use crate::parser::FailedLogin;

pub struct Alert {
    pub ip: IpAddr,
    pub timestamp: NaiveDateTime,
    pub window: i32
}

pub fn detector(events: Vec<FailedLogin>, threshold: usize, window: Duration) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = Vec::new();
    if threshold == 0 {
        return alerts
    }
    let mut groups: HashMap<IpAddr, Vec<NaiveDateTime>> = HashMap::new();
    // for event in events add ipaddr and timestamp to groups
    // if ipaddr in groups, add timestamp to existing ipaddr entry
    for event in events {
        groups
            .entry(event.ip)
            .or_insert_with(Vec::new)
            .push(event.timestamp);
    }
    // DEBUG 
    for (ip, mut timestamps) in &groups {
        // println!("Fails counted: {fail_count}");
        // println!("{ip}: {:?}", timestamps);
        if timestamps.len() < threshold {
            continue;
        } else {
            timestamps.sort();
            // for i in 0..=timestamps.len() - threshold  {
            //     let first = timestamps[i];
            //     let last = timestamps[i + threshold - 1];
            // }
        }

    }
    alerts
}