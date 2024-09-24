pub mod bac;
pub mod der_util;
pub mod iso7816;
pub mod mrz;
pub mod pace;
pub mod secure_messaging;


pub fn hexdump(buf: &[u8]) {
    let mut offset = 0;
    while offset < buf.len() {
        print!("{:08X}  ", offset);

        for i in 0..16 {
            if offset + i < buf.len() {
                print!(" {:02X}", buf[offset + i]);
            } else {
                print!("   ");
            }
        }

        print!(" |");
        for i in 0..16 {
            if offset + i >= buf.len() {
                break;
            }

            let b = buf[offset + i];
            if b >= b' ' && b <= b'~' {
                print!("{}", char::from_u32(b.into()).unwrap());
            } else {
                print!(".");
            }
        }
        println!("|");

        offset += 16;
    }
}
