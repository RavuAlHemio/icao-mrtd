pub mod bac;
pub mod crypt;
pub mod der_util;
pub mod iso7816;
pub mod mrz;
pub mod pace;
pub mod secure_messaging;


use std::fmt;


pub struct SliceHexdumper<'a>(&'a [u8]);
impl<'a> fmt::Display for SliceHexdumper<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02X}", *b)?;
        }
        Ok(())
    }
}
impl<'a> fmt::Debug for SliceHexdumper<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\n")?;
        let mut offset = 0;
        while offset < self.0.len() {
            write!(f, "{:08X}  ", offset)?;

            for i in 0..16 {
                if offset + i < self.0.len() {
                    write!(f, " {:02X}", self.0[offset + i])?;
                } else {
                    write!(f, "   ")?;
                }
            }

            write!(f, " |")?;
            for i in 0..16 {
                if offset + i >= self.0.len() {
                    break;
                }

                let b = self.0[offset + i];
                if b >= b' ' && b <= b'~' {
                    write!(f, "{}", char::from_u32(b.into()).unwrap())?;
                } else {
                    write!(f, ".")?;
                }
            }
            write!(f, "|")?;

            offset += 16;
        }
        Ok(())
    }
}


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
