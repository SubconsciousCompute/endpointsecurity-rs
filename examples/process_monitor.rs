fn main() {
    let mut client = endpointsecurity_rs::EsClient::new().unwrap();
    client
        .add_event(endpointsecurity_rs::EsEventType::NotifyExec)
        .subscribe();

    let mut count = 0;

    loop {
        let msg = client.recv_msg();
        println!("{:?}", msg);
        count += 1;
        if count == 10 {
            println!(
                "removed NotifyClose event: {}",
                client.unsubscribe(endpointsecurity_rs::EsEventType::NotifyExec)
            );
        }
    }
}
