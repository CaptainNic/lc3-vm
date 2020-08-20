use std::env;
use std::io::Read;
use std::fs::File;
use termios::*;

use lc3vm;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("Args: {:?}", args);
    let mut f = File::open(&args[1]).expect("File not found.");

    // Read file as u8's
    let mut buf = Vec::new();
    let file_size = f.read_to_end(&mut buf).expect("Unable to read file.");
    assert_eq!(file_size <= lc3vm::MEM_SIZE * 2, true);

    // The machine you're building this on is probably little endian
    // and LC3 is big endian, so time for the switcheroo.
    let mut memory = [0u16; lc3vm::MEM_SIZE];
    for (i, x) in buf.iter().enumerate() {
        match i % 2 {
            0 => {
                memory[i/2] += (*x as u16) << 8
            },
            1 => {
                memory[i/2] += *x as u16;
            },
            _ => {
                println!("Error writing file to vm memory.");
            }
        }
    }
    
    const STDIN_FILENO:i32 = 0;

    // Disable terminal input buffering
    let termios = termios::Termios::from_fd(STDIN_FILENO).unwrap();
    let mut new_termios = termios.clone();
    new_termios.c_iflag &= IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON;
    new_termios.c_lflag &= !(ICANON | ECHO); // no echo and canonical mode
    tcsetattr(STDIN_FILENO, TCSANOW, &mut new_termios).unwrap();

    // Create VM and run
    let mut vm = lc3vm::VM::new();
    vm.load(&memory);
    vm.run();

    // reset stdin to original settings
    tcsetattr(STDIN_FILENO, TCSANOW, &termios).unwrap();
}
