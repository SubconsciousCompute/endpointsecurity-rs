use endpointsecurity_rs::{EsClient, EsEventData, EsEventType};

fn main() {
    let mut client = EsClient::new().unwrap();
    client
        .add_event(EsEventType::AuthOpen)
        //.add_event(EsEventType::NotifyWrite)
        //.add_event(EsEventType::NotifyClose)
        .subscribe();

    loop {
        let msg = client.recv_msg().unwrap();
        msg.allow(&client);
        /*
        match data {
            EsEventData::NotifyWrite(file) => {
                if file.path.contains("/dev/ttys000") {
                    continue;
                }
                println!("{:?}", file);
            }
            a => {
                println!("{:?}", a);
            }
        }
         */
    }
}
