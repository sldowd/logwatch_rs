/* Detector-- Function: accepts Vec of FailedLogin structs, groups them by IP addr
and checks groups against threshold and window 
groups of events that meet threshold and window create and return alerts */


use chrono::{Duration, NaiveDateTime};
use std::net::IpAddr;
use std::collections::HashMap;
use crate::parser::FailedLogin;

#[derive(Debug, PartialEq)]
pub struct Alert {
    pub ip: IpAddr,
    pub timestamp: NaiveDateTime, 
    pub window: Duration
}

pub fn detector(events: Vec<FailedLogin>, threshold: usize, window: Duration) -> Vec<Alert> {
    let mut alerts: Vec<Alert> = Vec::new();
    if threshold == 0 {
        return alerts
    }
    let mut grouped_events: HashMap<IpAddr, Vec<NaiveDateTime>> = HashMap::new();
    // for event in events add ipaddr and timestamp to groups
    // if ipaddr in groups, add timestamp to existing ipaddr entry
    for event in events {
        grouped_events
            .entry(event.ip)
            .or_insert_with(Vec::new)
            .push(event.timestamp);
    }
    
    for (ip, timestamps) in &mut grouped_events {
        
        if timestamps.len() < threshold {
            continue;
        } else {
            timestamps.sort();
        }
        // Check each possible starting timestamp.
        for i in 0..=timestamps.len() - threshold {
            let start = timestamps[i];
            let end = timestamps[i + threshold - 1];

            if end - start <= window {
                alerts.push(Alert {
                    ip: *ip,
                    timestamp: end,
                    window
                });
                break
            }
        }
    }
    // DEBUG printing
    for alert in &alerts {
            let ip = alert.ip;
            println!("alert: {ip}");
        }
    alerts
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

use super::*;
    use crate::parser::parse_line;

    #[test]
    fn ignores_duration_longer_than_window() {
        let mut test_events: Vec<FailedLogin> = Vec::new();
        test_events.push(parse_line("Oct 22 14:04:05 web01 sshd[2230]: Failed password for ubuntu from 192.0.2.44 port 33001 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:07:40 web01 sshd[2260]: Failed password for ubuntu from 192.0.2.44 port 33050 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:12:15 web01 sshd[2301]: Failed password for ubuntu from 192.0.2.44 port 33102 ssh2").unwrap());
        
        assert!(
            detector(test_events, 3, Duration::seconds(60)).is_empty()
        );
    }

    #[test]
    fn catches_duration_shoter_than_window() {
        let mut test_events: Vec<FailedLogin> = Vec::new();
        test_events.push(parse_line("Oct 22 14:04:05 web01 sshd[2230]: Failed password for ubuntu from 192.0.2.44 port 33001 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:40 web01 sshd[2260]: Failed password for ubuntu from 192.0.2.44 port 33050 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:45 web01 sshd[2301]: Failed password for ubuntu from 192.0.2.44 port 33102 ssh2").unwrap());
        
        assert!(
            !detector(test_events, 3, Duration::seconds(60)).is_empty()
        );
    }

    #[test]
    fn exactly_one_alert_per_ip() {
        let mut test_events: Vec<FailedLogin> = Vec::new();
        test_events.push(parse_line("Oct 22 14:04:05 web01 sshd[2230]: Failed password for ubuntu from 192.0.2.44 port 33001 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:40 web01 sshd[2260]: Failed password for ubuntu from 192.0.2.44 port 33050 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:45 web01 sshd[2301]: Failed password for ubuntu from 192.0.2.44 port 33102 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:55 web01 sshd[2230]: Failed password for ubuntu from 192.0.2.44 port 33001 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:05:05 web01 sshd[2260]: Failed password for ubuntu from 192.0.2.44 port 33050 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:05:15 web01 sshd[2301]: Failed password for ubuntu from 192.0.2.44 port 33102 ssh2").unwrap());

        assert_eq!((detector(test_events, 3, Duration::seconds(60)).len()), 1);
    }

    #[test]
    fn verify_ipaddr_returned() {
        let mut test_events: Vec<FailedLogin> = Vec::new();
        test_events.push(parse_line("Oct 22 14:04:05 web01 sshd[2230]: Failed password for ubuntu from 192.0.2.44 port 33001 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:40 web01 sshd[2260]: Failed password for ubuntu from 192.0.2.44 port 33050 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:45 web01 sshd[2301]: Failed password for ubuntu from 192.0.2.44 port 33102 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:04:55 web01 sshd[2230]: Failed password for ubuntu from 192.0.2.44 port 33001 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:05:05 web01 sshd[2260]: Failed password for ubuntu from 192.0.2.44 port 33050 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:05:15 web01 sshd[2301]: Failed password for ubuntu from 192.0.2.44 port 33102 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:03:13 web01 sshd[2203]: Failed password for invalid user admin from 203.0.113.5 port 52120 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:03:17 web01 sshd[2207]: Failed password for invalid user test from 203.0.113.5 port 52131 ssh2").unwrap());
        test_events.push(parse_line("Oct 22 14:03:19 web01 sshd[2209]: Failed password for root from 203.0.113.5 port 52140 ssh2").unwrap());
        let alerts = detector(test_events, 3, Duration::seconds(60));
        assert!(alerts.len() == 2);
        assert!(alerts.iter().any(|a| a.ip == IpAddr::from_str("192.0.2.44").unwrap()));
        assert!(alerts.iter().any(|a| a.ip == IpAddr::from_str("203.0.113.5").unwrap()));
    }


}