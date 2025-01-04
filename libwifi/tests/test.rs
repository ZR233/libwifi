use std::io::Write;

use anyhow::Result;
use pcap::{Capture, Packet};
use radiotap::Radiotap;
use tempfile::NamedTempFile;


#[test]
fn test_wifi6() {
    let file_data = include_bytes!("../../data/wifi6.pcap");
    let mut tmpfile = NamedTempFile::new().unwrap();
    tmpfile.write_all(file_data).unwrap();

    let mut cap = Capture::from_file(tmpfile.path()).unwrap();

    while let Ok(packet) = cap.next_packet() {
        handle_packet(packet).unwrap();
    }
}

pub fn handle_packet(packet: Packet) -> Result<()> {
    // At first, we look at the
    let radiotap = match Radiotap::from_bytes(packet.data) {
        Ok(radiotap) => radiotap,
        Err(error) => {
            println!(
                "Couldn't read packet data with Radiotap: {:?}, error {error:?}",
                &packet.data
            );
            return Ok(());
        }
    };

    let payload = &packet.data[radiotap.header.length..];
    match libwifi::parse_frame(payload, false) {
        Ok(frame) => {
            println!("Got frame: {frame:?}");
        }
        Err(err) => {
            println!("Error during parsing :\n{err}");
            if let libwifi::error::Error::Failure(_, data) = err {
                println!("{data:?}")
            }
        }
    };

    Ok(())
}
