extern crate argparse;
extern crate pcap;

use argparse::{ArgumentParser, StoreTrue};
use pcap::{Capture, Device};

///
/// Procedure to print available devices
/// vec_devices : Vector of Device objects
///
fn print_available_devices<'a> (vec_devices : &'a Vec<Device>) {
    println!("-Available devices:", );
    for device in vec_devices {
        match device {
            _ => println!("\t* Device {:?} : {:?}", device.name, device.desc),
        }
    }
}

///
/// Simple procedure to get the WLP2S0 device
/// wlp2s0_device : A single Device structure to save the wlp2s0 device
/// vec_devices : A vector of Device objects
///
fn get_wlp2s0_device<'a> (wlp2s0_device : &'a mut Device, vec_devices : &'a Vec<Device>) {
    for device in vec_devices {
        match &*device.name {
            "wlp2s0" => {
                wlp2s0_device.name = device.name.clone();
                wlp2s0_device.desc = device.desc.clone();
                println!("-wlp2s0 device has been captured!");
            },
            _ => ()
        }
    }
}

fn main() {

    // Arguments
    let mut capture_devices : bool = false;
    let mut print_devices : bool = false;
    let mut verbose : bool = false;
    {
        let mut argparse = ArgumentParser::new();
        argparse.set_description("Hot Rust tool to sniff what you want...");
        argparse.refer(&mut capture_devices)
            .add_option(&["-c", "--capture_devices"], StoreTrue,
            "Capture external devices");
        argparse.refer(&mut print_devices)
            .add_option(&["-p", "--print_devices"], StoreTrue,
            "Print devices found");
        argparse.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
            "Be verbose");
        // Other options
        argparse.parse_args_or_exit();
    }

    // For tools
    let devices = Device::list();
    let mut wlp2s0_device : Device = Device::lookup().unwrap();
    match devices {
        Ok(vec_devices) => {
            print_available_devices(&vec_devices);
            get_wlp2s0_device(&mut wlp2s0_device, &vec_devices);
        }
        Err(_) => {
            println!("No devices found...");
            std::process::exit(1);
        },
    }
    // Verify if the device name is "wlp2s0"
    if wlp2s0_device.name != "wlp2s0" {
        std::process::exit(1);
    }

    // Capture the device
    let mut cap = Capture::from_device(wlp2s0_device).unwrap()
                        .promisc(true)
                        .snaplen(5000)
                        .open().unwrap();

    // Create the file to save in results
    let mut file : pcap::Savefile =
        match cap.savefile("./rslts/rslts.pcap") {
            Ok(f) => f,
            Err(_) => std::process::exit(1),
        };

    // While packets come, capture them...
    while let Ok(packet) = cap.next() {
        println!("received packet!");
        file.write(&packet);
    }
}
