use std::{env::current_dir, path::PathBuf, str::FromStr};

use libwifi::{
    Addresses,
    frame::{Frame::QosData, components::MacAddress},
};
use pcap::Capture;
use radiotap::Radiotap;

fn data_dir() -> PathBuf {
    current_dir().unwrap().parent().unwrap().join("data")
}

#[test]
fn test_asus() {
    let mut cap = Capture::from_file(data_dir().join("asus.pcap")).unwrap();
    let packet = cap.next_packet().unwrap();

    // At first, we look at the
    let radiotap = Radiotap::from_bytes(packet.data).unwrap();

    let payload = &packet.data[radiotap.header.length..];

    let frame = libwifi::parse_frame(payload, false).unwrap();

    if let QosData(data) = frame {
        let ta = data.header.ta();
        let da = data.header.da();
        let ra = data.header.ra();
        let sa = data.header.sa().unwrap();
        let bssid = *data.header.bssid().unwrap();

        // 手机发送
        let source = MacAddress::from_str("f4:63:fc:c7:ad:92").unwrap();
        assert_eq!(source, sa);

        let ap = MacAddress::from_str("04:92:26:37:89:d8").unwrap();
        assert_eq!(ap, bssid);

        println!(
            "TA: {}, RA: {}, DA: {}, SA {},bssid: {}",
            ta, ra, da, sa, bssid
        );
    }
}
