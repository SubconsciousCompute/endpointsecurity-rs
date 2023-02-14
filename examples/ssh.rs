use endpointsecurity_rs::{EsAddressType, EsClient, EsEventData, EsEventType};

fn main() {
    let mut client = EsClient::new().unwrap();
    client
        .add_event(EsEventType::NotifyOpenSSHLogin)
        .subscribe();

    loop {
        let msg = client.rx.recv().unwrap();
        if let Some(ref data) = msg.event_data {
            match data {
                EsEventData::NotifyOpenSSHLogin(ssh_deets) => {
                    let addr = match &ssh_deets.source_address {
                        EsAddressType::None => panic!("Sadge"),
                        EsAddressType::Ipv4(addr) => addr.to_string(),
                        EsAddressType::Ipv6(addr) => addr.to_string(),
                        EsAddressType::NamedSocket(addr) => addr.clone(),
                    };
                    println!(
                        "Someone from {} is trying to connect as {}",
                        addr, ssh_deets.username
                    );
                }
                _ => {}
            }
        }
    }
}
