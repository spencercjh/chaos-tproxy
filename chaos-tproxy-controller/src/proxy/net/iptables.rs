use crate::proxy::net::bridge::{ip_netns, NetEnv};

pub fn set_iptables<'a>(
    net_env: &'a NetEnv,
    proxy_ports: Option<&'a str>,
    listen_port: &'a str,
    device_mac: &'a str,
) -> Vec<Vec<&'a str>> {
    tracing::info!(
        "Setting iptables with net_env: {:?}, proxy_ports: {:?}, listen_port: {}, device_mac: {}",
        net_env,
        proxy_ports,
        listen_port,
        device_mac
    );

    let cmdv = match proxy_ports {
        Some(proxy_ports) => {
            let cmd = vec![
                "iptables",
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                proxy_ports,
                "-j",
                "TPROXY",
                "--tproxy-mark",
                "0x1/0x1",
                "--on-port",
                listen_port,
            ];
            tracing::info!("Executing command: {:?}", cmd);
            ip_netns(&net_env.netns, cmd)
        }
        None => {
            let cmd = vec![
                "iptables",
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "-j",
                "TPROXY",
                "--tproxy-mark",
                "0x1/0x1",
                "--on-port",
                listen_port,
            ];
            tracing::info!("Executing command: {:?}", cmd);
            ip_netns(&net_env.netns, cmd)
        }
    };

    let result = vec![
        {
            let cmd = vec!["iptables", "-t", "mangle", "-N", "DIVERT"];
            tracing::info!("Executing command: {:?}", cmd);
            ip_netns(&net_env.netns, cmd)
        },
        {
            let cmd = vec![
                "iptables",
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "-m",
                "socket",
                "-j",
                "DIVERT",
            ];
            tracing::info!("Executing command: {:?}", cmd);
            ip_netns(&net_env.netns, cmd)
        },
        {
            let cmd = vec![
                "iptables",
                "-t",
                "mangle",
                "-A",
                "DIVERT",
                "-j",
                "MARK",
                "--set-mark",
                "1",
            ];
            tracing::info!("Executing command: {:?}", cmd);
            ip_netns(&net_env.netns, cmd)
        },
        {
            let cmd = vec!["iptables", "-t", "mangle", "-A", "DIVERT", "-j", "ACCEPT"];
            tracing::info!("Executing command: {:?}", cmd);
            ip_netns(&net_env.netns, cmd)
        },
        cmdv,
        {
            let cmd = vec![
                "ebtables-legacy",
                "-t",
                "broute",
                "-A",
                "BROUTING",
                "-p",
                "IPv4",
                "--ip-proto",
                "6",
                "--ip-dport",
                "!",
                "22",
                "--ip-sport",
                "!",
                "22",
                "-j",
                "redirect",
                "--redirect-target",
                "DROP",
            ];
            tracing::info!("Executing command: {:?}", cmd);
            ip_netns(&net_env.netns, cmd)
        },
        {
            let cmd = vec![
                "ebtables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                &net_env.device,
                "-j",
                "dnat",
                "--to-dst",
                device_mac,
                "--dnat-target",
                "ACCEPT",
            ];
            tracing::info!("Executing command: {:?}", cmd);
            cmd
        },
    ];

    tracing::info!("Iptables rules set: {:?}", result);
    result
}

pub fn set_iptables_safe<'a>(net_env: &'a NetEnv, device_mac: &'a str) -> Vec<Vec<&'a str>> {
    let cmds = vec![
        vec![
            "iptables",
            "-t",
            "mangle",
            "-I",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "81:1025",
            "-s",
            &net_env.ip,
            "-j",
            "ACCEPT",
        ],
        vec![
            "iptables",
            "-t",
            "mangle",
            "-I",
            "PREROUTING",
            "-p",
            "tcp",
            "--sport",
            "81:1025",
            "-d",
            &net_env.ip,
            "-j",
            "ACCEPT",
        ],
        vec![
            "iptables",
            "-t",
            "mangle",
            "-I",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "1:81",
            "-s",
            &net_env.ip,
            "-j",
            "ACCEPT",
        ],
        vec![
            "iptables",
            "-t",
            "mangle",
            "-I",
            "PREROUTING",
            "-p",
            "tcp",
            "--sport",
            "1:81",
            "-d",
            &net_env.ip,
            "-j",
            "ACCEPT",
        ],
        vec![
            "ebtables",
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            &net_env.device,
            "-j",
            "dnat",
            "--to-dst",
            device_mac,
            "--dnat-target",
            "ACCEPT",
        ],
    ];

    for cmd in &cmds {
        tracing::info!("Executing command: {:?}", cmd);
    }

    cmds.into_iter()
        .map(|cmd| ip_netns(&net_env.netns, cmd))
        .collect()
}

pub fn clear_ebtables() -> Vec<&'static str> {
    vec!["ebtables", "-t", "nat", "-F"]
}
