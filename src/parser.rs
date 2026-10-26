use chrono::NaiveDateTime;
use std::net::IpAddr;

#[derive(Debug, PartialEq)]
pub struct FailedLogin {
    pub timestamp: NaiveDateTime,
    pub user: String,
    pub ip: IpAddr,
}

/// Parses one OpenSSH line such as:
/// `Oct 20 10:15:01 host sshd[1234]: Failed password for root from 203.0.113.5 port 22 ssh2`
/// Returns None for any line that is not a failed password attempt.
pub fn parse_line(line: &str) -> Option<FailedLogin> {

    if line.contains("Failed password") && line.contains("sshd") {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        // find position of anchor words
        let for_pos = tokens.iter().position(|&t| t == "for")?;
        let from_pos = tokens.iter().position(|&t| t == "from")?;
        
        let user = if tokens.get(for_pos + 1)? == &"invalid" {
            tokens.get(for_pos + 3)?
        } else {
            tokens.get(for_pos + 1)?
        };
        let ip: IpAddr = tokens.get(from_pos + 1)?.parse().ok()?;
        let ts = format!("2026 {} {} {}", tokens[0], tokens[1], tokens[2]);
        let timestamp = NaiveDateTime::parse_from_str(&ts, "%Y %b %d %H:%M:%S").ok()?;
        
        Some(FailedLogin { timestamp, user: user.to_string(), ip })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_password_line() {
        use chrono::NaiveDate;
        let line = "Oct 22 14:12:15 web01 sshd[2301]: Failed password for ubuntu from 192.0.2.44 port 33102 ssh2";
        let expected = FailedLogin {
        timestamp: NaiveDate::from_ymd_opt(2026, 10, 22)
            .unwrap()
            .and_hms_opt(14, 12, 15)
            .unwrap(),
        user: "ubuntu".to_string(),
        ip: "192.0.2.44".parse().unwrap(),
    };
        assert_eq!(parse_line(line), Some(expected));
    }

    #[test]
    fn ignores_unrelated_lines() {
        let line = "Oct 22 14:01:09 web01 sshd[2101]: Accepted password for sarah from 198.51.100.7 port 40022 ssh2";
        assert_eq!(parse_line(line), None);
    }

    #[test]
    fn rejects_malformed_ip() {
        let line = "Oct 22 14:12:15 web01 sshd[2301]: Failed password for ubuntu from 203.0.113.999 port 33102 ssh2";
        assert_eq!(parse_line(line), None);
    }
}