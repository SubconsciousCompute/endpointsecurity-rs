use endpointsecurity_rs::{EsClient, EsEventData, EsEventType};

fn main() {
    let mut client = EsClient::new().unwrap();
    client.add_event(EsEventType::NotifyExec).subscribe();

    loop {
        let msg = client.recv_msg().unwrap();
        if let Some(ref data) = msg.event_data {
            match data {
                EsEventData::NotifyExec(proc) => {
                    println!("{:?}", proc);
                }
                _ => {}
            }
        }
    }
}
