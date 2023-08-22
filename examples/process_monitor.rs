use endpointsecurity_rs::{Client, EventType};

fn main() {
    let mut client = Client::new().unwrap();
    client
        .subscribe(&[EventType::NotifyCreate, EventType::NotifyWrite])
        .unwrap();

    println!("{:?}", client.subscriptions());
}
