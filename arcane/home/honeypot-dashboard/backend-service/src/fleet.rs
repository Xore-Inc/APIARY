//! Addresses of the sensor fleet, independent of the host running the API.
//! The VPS relay and homeserver sensor addresses describe captured traffic;
//! moving an HTTP API to another machine must not change their meaning.

use std::{net::Ipv4Addr, sync::OnceLock};

pub const DEFAULT_TUNNEL_PEER_IP: &str = "10.8.0.1";
pub const DEFAULT_TUNNEL_SENSOR_IP: &str = "10.8.0.2";

fn validated_ip(name: &str, value: &str) -> Result<String, String> {
    let value = value.trim();
    value
        .parse::<Ipv4Addr>()
        .map(|ip| ip.to_string())
        .map_err(|_| format!("{name} must be an IPv4 address"))
}

fn configured_ip(name: &str, default: &str) -> String {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
    validated_ip(name, &value).unwrap_or_else(|error| panic!("{error}"))
}

pub fn tunnel_peer_ip() -> &'static str {
    static IP: OnceLock<String> = OnceLock::new();
    IP.get_or_init(|| configured_ip("HONEYPOT_TUNNEL_PEER_IP", DEFAULT_TUNNEL_PEER_IP))
}

pub fn tunnel_sensor_ip() -> &'static str {
    static IP: OnceLock<String> = OnceLock::new();
    IP.get_or_init(|| configured_ip("HONEYPOT_TUNNEL_SENSOR_IP", DEFAULT_TUNNEL_SENSOR_IP))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_addresses_accept_host_specific_ipv4() {
        assert_eq!(validated_ip("peer", " 192.0.2.7 "), Ok("192.0.2.7".into()));
    }

    #[test]
    fn malformed_fleet_addresses_fail_closed() {
        for value in ["", "not-an-ip", "2001:db8::1", "10.8.0.1:1234"] {
            assert_eq!(
                validated_ip("peer", value),
                Err("peer must be an IPv4 address".into())
            );
        }
    }
}
