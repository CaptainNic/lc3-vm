use std::env;
use std::error::Error;
use std::io::Read;
use std::fs::File;
use lc3vm;

fn main() -> Result<(), Box<dyn Error>> {
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

    let mut vm = lc3vm::VM::new();
    vm.load(&memory);
    vm.run();

    Ok(())
}
