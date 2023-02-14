use endpointsecurity_rs::{EsClient, EsEventData, EsEventType};

fn main() {
    let mut client = EsClient::new().unwrap();
    client.add_event(EsEventType::AuthRename).subscribe();

    loop {
        let ev = client.rx.recv().unwrap();
        if let Some(ref data) = ev.event_data {
            match data {
                EsEventData::AuthRename(info) => {
                    if info.source.path.contains("/Users/idipot/subcom.tech/test") {
                        println!("{:?}", ev);
                        ev.deny(&client);
                    } else {
                    }
                }
                _ => {}
            }
        }
    }
}
