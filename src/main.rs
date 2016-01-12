extern crate argparse;
extern crate pcap;

use argparse::{ArgumentParser, Store, StoreTrue};
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
/// Simple procedure to get the requested_device device
/// requested_device : A single Device structure to save the requested_device device
/// vec_devices : A vector of Device objects
///
fn get_requested_device<'a> (requested_device_s : &str, requested_device : &'a mut Device, vec_devices : &'a Vec<Device>) {
    for device in vec_devices {
        if &*device.name == requested_device_s {
                requested_device.name = device.name.clone();
                requested_device.desc = device.desc.clone();
                println!("-{} device has been captured!", requested_device_s);
        };
    };
}

fn main() {

    let mut requested_device : Device = Device::lookup().unwrap();

    // Arguments
    let mut print_devices : bool = false;
    let mut requested_device_s : String = "wlp2s0".to_string();
    let mut verbose : bool = false;
    {
        let mut argparse = ArgumentParser::new();
        argparse.set_description("Hot Rust tool to sniff what you want...");
        argparse.refer(&mut print_devices)
            .add_option(&["-p", "--print_devices"], StoreTrue,
            "Print devices found");
        argparse.refer(&mut requested_device_s)
            .add_option(&["-d", "--device"], Store,
            "Request a device");
        argparse.refer(&mut verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
            "Be verbose");
        // Other options
        argparse.parse_args_or_exit();
    }

    // For tools
    let devices = Device::list();

    println!("requested_device : {}", requested_device_s);

    // Begin
    match devices {
        Ok(vec_devices) => {
            if print_devices {
                print_available_devices(&vec_devices);
                std::process::exit(0);
            }
            get_requested_device(&requested_device_s, &mut requested_device, &vec_devices);
        }
        Err(_) => {
            println!("No devices found...");
            std::process::exit(1);
        },
    }

    if requested_device.name != requested_device_s {
        std::process::exit(1);
    }

    // Capture the device
    let mut cap = Capture::from_device(requested_device).unwrap()
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
