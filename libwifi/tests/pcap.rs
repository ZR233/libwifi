use core::panic;
use std::{env::current_dir, path::PathBuf, str::FromStr};

use libwifi::{
    Addresses,
    frame::{Frame, components::MacAddress},
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

    // 手机发送
    let want_source = MacAddress::from_str("f4:63:fc:c7:ad:92").unwrap();
    let want_dest = MacAddress::from_str("04:92:26:37:89:d8").unwrap();

    // At first, we look at the
    let radiotap = Radiotap::from_bytes(packet.data).unwrap();

    let payload = &packet.data[radiotap.header.length..];

    let frame = libwifi::parse_frame(payload, false).unwrap();

    if let Frame::QosData(data) = frame {
        let ta = data.header.ta();
        let da = data.header.da();
        let ra = data.header.ra();
        let sa = data.header.sa().unwrap();
        let bssid = *data.header.bssid().unwrap();

        let mut src = *data.header.src().unwrap();
        let mut dest = *data.header.dest();

        println!(
            "TA: {}, RA: {}, DA: {}, SA {},bssid: {} src: {}, dest: {}, to_ds: {} from_ds: {}",
            ta,
            ra,
            da,
            sa,
            bssid,
            src,
            dest,
            data.header.frame_control.to_ds(),
            data.header.frame_control.from_ds()
        );

        if data.header.frame_control.from_ds() && sa != bssid {
            src = sa;
            dest = bssid;
        }

        assert_eq!(src, want_source);

        assert_eq!(dest, want_dest);
    }
}

#[test]
fn test_ap() {
    let mut cap = Capture::from_file(data_dir().join("asus.pcap")).unwrap();

    for _ in 0..2 {
        cap.next_packet().unwrap();
    }

    let packet = cap.next_packet().unwrap();

    // At first, we look at the
    let radiotap = Radiotap::from_bytes(packet.data).unwrap();

    let payload = &packet.data[radiotap.header.length..];

    let frame = libwifi::parse_frame(payload, false).unwrap();

    let beacon = match frame {
        Frame::Beacon(beacon) => beacon,
        _ => panic!("Not a beacon"),
    };

    println!("{:?}", beacon.station_info.ht_capabilities);

    let bssid = *beacon.bssid().unwrap();

    let ap = MacAddress::from_str("04:92:26:37:89:d8").unwrap();

    assert_eq!(bssid, ap);
}

#[test]
fn test_xiaomi() {
    let mut cap = Capture::from_file(data_dir().join("xiaomi.pcap")).unwrap();
    let packet = cap.next_packet().unwrap();

    let src = MacAddress::from_str("78:8b:2a:66:3c:d6").unwrap();
    let dest = MacAddress::from_str("04:92:26:37:89:d8").unwrap();

    // At first, we look at the
    let radiotap = Radiotap::from_bytes(packet.data).unwrap();

    let payload = &packet.data[radiotap.header.length..];

    let frame = libwifi::parse_frame(payload, false).unwrap();

    if let Frame::BlockAck(data) = frame {
        println!("s {},  d {}", data.source, data.destination);
        assert_eq!(src, data.source);
        assert_eq!(dest, data.destination);
    }
}

#[test]
fn test_xiaomi2() {
    // sta 发往 ap

    let mut cap = Capture::from_file(data_dir().join("xiaomi.pcap")).unwrap();
    let packet = cap.next_packet().unwrap();
    let packet = cap.next_packet().unwrap();

    let want_src = MacAddress::from_str("78:8b:2a:66:3c:d6").unwrap();
    let want_dest = MacAddress::from_str("04:92:26:37:89:d8").unwrap();

    // At first, we look at the
    let radiotap = Radiotap::from_bytes(packet.data).unwrap();

    let payload = &packet.data[radiotap.header.length..];

    let frame = libwifi::parse_frame(payload, false).unwrap();

    if let Frame::QosData(data) = frame {
        if data.header.frame_control.to_ds() {
            let src = data.header.ta();
            let dest = *data.header.bssid().unwrap();

            assert_eq!(src, want_src);
            assert_eq!(dest, want_dest);
        }
    } else {
        panic!("Not a QosData");
    }
}
