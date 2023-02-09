fn main() {
    let mut client = endpointsecurity_rs::EsClient::new().unwrap();
    client
        .add_event(endpointsecurity_rs::EsEventType::NotifyExec)
        .subscribe();

    loop {
        let msg = client.recv_msg();
        println!("{:?}", msg);
    }
}
