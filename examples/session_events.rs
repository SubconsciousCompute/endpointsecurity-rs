use endpointsecurity_rs::{EsClient, EsEventData, EsEventType};

fn main() {
    let mut client = EsClient::new().unwrap();
    client
        .add_event(EsEventType::NotifyLWSessionLock)
        .add_event(EsEventType::NotifyLWSessionUnlock)
        .subscribe();

    loop {
        let evt = client.recv_msg().unwrap();
        println!("{:?}", evt);
    }
}
