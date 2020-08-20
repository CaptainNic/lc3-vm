use nix::sys::select::{select, FdSet};
use nix::sys::time::{TimeVal, TimeValLike};
use std::io::Read;

pub struct VM {
  memory: Memory,
  reg: [u16; R_COUNT],
  running: bool
}

// Configuration
pub const MEM_SIZE: usize = 1 << 16;

struct Memory {
  mem: [u16; MEM_SIZE]
}

impl Memory {
  fn new() -> Memory {
    Memory {
      mem: [0u16; MEM_SIZE]
    }
  }

  fn write(&mut self, addr: usize, value: u16) {
    self.mem[addr] = value;
  }

  fn read(&mut self, addr: usize) -> u16 {
    match addr {
      MMR_KBSR => {
        if self.check_key() {
          self.mem[MMR_KBSR] = 1 << 15;
          self.mem[MMR_KBDR] = self.get_char();
        } else {
          self.mem[MMR_KBSR] = 0;
        }
        self.mem[addr]
      },
      _ => {
        self.mem[addr]
      }
    }
  }

  fn check_key(&self) -> bool {
    const STDIN_FILENO: i32 = 0;

    let mut fd = FdSet::new();
    fd.insert(STDIN_FILENO);

    match select(None, &mut fd, None, None, &mut TimeVal::zero()) {
      Ok(value) => value == 1,
      Err(_) => false,
    }
  }

  fn get_char(&self) -> u16 {
    let mut buffer = [0; 1];
    std::io::stdin()
      .read_exact(&mut buffer)
      .expect("unable to read from stdin");

    u16::from(buffer[0])
  }
}

// Condition Flags
const FL_POS: u16 = 1 << 0; // Positive
const FL_ZRO: u16 = 1 << 1; // Zero
const FL_NEG: u16 = 1 << 2; // Negative

// Memory Mapped Registers
// TODO: other MMR's
const MMR_KBSR: usize = 0xFE00; // keyboard status register
const MMR_KBDR: usize = 0xFE02; // keyboard data register

// Register ID's
const R_R0:    usize =  0;
#[allow(unused)]
const R_R1:    usize =  1;
#[allow(unused)]
const R_R2:    usize =  2;
#[allow(unused)]
const R_R3:    usize =  3;
#[allow(unused)]
const R_R4:    usize =  4;
#[allow(unused)]
const R_R5:    usize =  5;
#[allow(unused)]
const R_R6:    usize =  6;
const R_R7:    usize =  7;
const R_PC:    usize =  8;
const R_COND:  usize =  9;
const R_COUNT: usize = 10;

#[derive(Debug)]
enum OpCode {
  BR,  // Branch
  ADD, // Add
  LD,  // Load
  ST,  // Store
  JSR, // Jump Register
  AND, // Bitwise And
  LDR, // Load Register
  STR, // Store Register
  RTI, // UNUSED
  NOT, // Bitwise Not
  LDI, // Load Indirect
  STI, // Store Indirect
  JMP, // Jump
  RES, // RESERVED
  LEA, // Load Effective Address
  TRAP // Execute TRAP
}

impl OpCode {
  fn from_instr(instr: u16) -> Result<OpCode, &'static str> {
    match instr >> 12 {
       0 => Ok(OpCode::BR),
       1 => Ok(OpCode::ADD),
       2 => Ok(OpCode::LD),
       3 => Ok(OpCode::ST),
       4 => Ok(OpCode::JSR),
       5 => Ok(OpCode::AND),
       6 => Ok(OpCode::LDR),
       7 => Ok(OpCode::STR),
       8 => Ok(OpCode::RTI),
       9 => Ok(OpCode::NOT),
      10 => Ok(OpCode::LDI),
      11 => Ok(OpCode::STI),
      12 => Ok(OpCode::JMP),
      13 => Ok(OpCode::RES),
      14 => Ok(OpCode::LEA),
      15 => Ok(OpCode::TRAP),
      _ => Err("Unrecognized OpCode")
    }
  }
}

#[derive(Debug)]
enum TrapCode {
  GETC,
  OUT,
  PUTS,
  IN,
  PUTSP,
  HALT
}

impl TrapCode {
  fn from_trapvect8(trapvec: u8) -> Result<TrapCode, &'static str> {
    match trapvec {
      0x20 => Ok(TrapCode::GETC),
      0x21 => Ok(TrapCode::OUT),
      0x22 => Ok(TrapCode::PUTS),
      0x23 => Ok(TrapCode::IN),
      0x24 => Ok(TrapCode::PUTSP),
      0x25 => Ok(TrapCode::HALT),
      _ => Err("Unrecognized TrapCode")
   }
  }
}

// Extends the sign bit to u16 length
fn sign_extend(x: u16, bits: usize) -> u16 {
  match x >> (bits - 1) == 1 {
    true => { x | (0xFFFF << bits) },
    false => { x }
  }
}

impl VM {
  pub fn new() -> VM {
    VM {
      memory: Memory::new(),
      reg: [0u16; R_COUNT],
      running: false
    }
  }

  pub fn load(&mut self, program: &[u16]) {
    // First address should be the start address.
    self.reg[R_PC] = program[0];

    // The rest is program data
    let mut curr_addr = self.reg[R_PC] as usize;
    for mem in program[1..].iter() {
      if curr_addr as usize == MEM_SIZE {
        break;
      }
      self.memory.write(curr_addr as usize, *mem);
      curr_addr += 1;
    }
  }

  pub fn run(&mut self) {
    // Begin execution
    self.running = true;
    while self.running {
      // Fetch instruction
      let instr = self.memory.read(self.reg[R_PC] as usize);
      print!("PC: 0x{:4X}\t", self.reg[R_PC]);
      self.reg[R_PC] = self.reg[R_PC].wrapping_add(1);

      let op = OpCode::from_instr(instr).unwrap();
      // std::thread::sleep_ms(100);
      match op {
        OpCode::ADD => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   dr   |  sr1   | 0| 0  0|  sr2   |
          // |  op code  |   dr   |  sr1   | 1|     imm5     |
          let dr:usize  = ((instr >> 9) & 0b111) as usize;
          let sr1:usize = ((instr >> 6) & 0b111) as usize;
          match (instr >> 5) & 0b1 {
            0 => {
              let sr2 = (instr & 0b111) as usize;
              self.reg[dr] = self.reg[sr1].wrapping_add(self.reg[sr2]);
              println!("ADD\tR{} R{} R{} (0x{:X} + 0x{:X} = 0x{:X})",
                dr, sr1, sr1,
                self.reg[sr1],
                self.reg[sr2],
                self.reg[sr1].wrapping_add(self.reg[sr2]));
            },
            1 => {
              let imm5 = sign_extend(instr & 0x1F, 5);
              self.reg[dr] = self.reg[sr1].wrapping_add(imm5);
              println!("ADD\tR{} R{} 0x{:X} (0x{:X} + 0x{:X} = 0x{:X})",
                dr, sr1, imm5,
                self.reg[sr1], imm5, self.reg[sr1].wrapping_add(imm5));
            }
            _ => () // appease compiler
          }
          self.update_flags(dr);
        },
        OpCode::AND => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   dr   |  sr1   | 0| 0  0|  sr2   |
          // |  op code  |   dr   |  sr1   | 1|     imm5     |
          print!("AND\t");
          let dr:usize  = ((instr >> 9) & 0b111) as usize;
          print!("R{}\t", dr);
          let sr1:usize = ((instr >> 6) & 0b111) as usize;
          print!("R{}\t", dr);
          match (instr >> 5) & 0b1 {
            0 => {
              let sr2 = (instr & 0b111) as usize;
              println!("R{}\t", dr);
              self.reg[dr] = self.reg[sr1] & self.reg[sr2];
            },
            1 => {
              let imm5 = sign_extend(instr & 0x1F, 5);
              println!("0x{:X}\t", dr);
              self.reg[dr] = self.reg[sr1] & imm5;
            }
            _ => () // appease compiler
          }
          self.update_flags(dr);
        },
        OpCode::BR => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  | n| z| p|         PCoffset9        |
          print!("BR");
          let flags:u16 = (instr >> 9) & 0b111;
          if flags >> 2 == 1 { print!("n") }
          if flags >> 1 == 1 { print!("z") }
          if flags >> 0 == 1 { print!("p") }

          let offset = sign_extend(instr & 0x1FF, 9);
          println!(" 0x{:X}", offset);
          // BR is equivalent to BRnzp, it always branches
          if flags == 0 || self.reg[R_COND] & flags != 0 {
            self.reg[R_PC] = self.reg[R_PC].wrapping_add(offset);
          }
        },
        OpCode::JMP => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   000  | BaseR  |      000000     | JMP
          // |  op code  |   000  |   000  |      000000     | RET
          let base_reg:usize  = ((instr >> 6) & 0b111) as usize;
          match base_reg {
            0 => {
              println!("RET");
              // RET - set PC to R7, which contains the addr
              //  to the instruction following the call instr.
              self.reg[R_PC] = self.reg[R_R7];
            },
            _ => {
              let addr = self.reg[base_reg];
              println!("JMP R{} (0x{:4X})", base_reg, addr);
              // JMP - set PC to addr in BaseR
              self.reg[R_PC] = addr;
            }
          }
        },
        OpCode::JSR => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  | 1|            PCoffset11          | JSR
          // |  op code  | 0|  00 |  BaseR |      000000     | JSRR

          // Set next instr as return address in R7
          self.reg[R_R7] = self.reg[R_PC];
          let jump_to_reg:bool = instr >> 11 == 0;
          match jump_to_reg {
            false => {
              // JSR - jump to PCoffset11
              let offset = sign_extend(instr & 0x7FF, 11);
              println!("JSR\t0x{:X}", offset);
              self.reg[R_PC] = self.reg[R_PC].wrapping_add(offset);
            },
            true => {
              // JSRR - jump to BaseR
              let base_reg = ((instr >> 6) & 0b111) as usize;
              println!("JSRR\tR{} (0x{:X})", base_reg, self.reg[base_reg]);
              self.reg[R_PC] = self.reg[base_reg];
            }
          }
        },
        OpCode::LD => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   dr   |         PCoffset9        |
          let dr:usize = ((instr >> 9) & 0b111) as usize;
          let offset = sign_extend(instr & 0x01FF, 9);
          let addr = self.reg[R_PC].wrapping_add(offset) as usize;
          self.reg[dr] = self.memory.read(addr);
          self.update_flags(dr);
          println!("LD\tR{} 0x{:X} (0x{:X})", dr, offset, addr);
        },
        OpCode::LDI => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   dr   |         PCoffset9        |
          let dr:usize = ((instr >> 9) & 0b111) as usize;
          let offset = sign_extend(instr & 0x01FF, 9);
          let addr = self.reg[R_PC].wrapping_add(offset) as usize;
          let indirect_addr = self.memory.read(addr) as usize;
          self.reg[dr] = self.memory.read(indirect_addr);
          self.update_flags(dr);
          println!("LDI\tR{} 0x{:X}", dr, offset);
        },
        OpCode::LDR => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   dr   |  baseR |     offset6     |
          let dr = ((instr >> 9) & 0b111) as usize;
          let base_reg = ((instr >> 6) & 0b111) as usize;
          let offset = sign_extend(instr & 0x3F, 6);
          let addr = self.reg[base_reg].wrapping_add(offset) as usize;
          self.reg[dr] = self.memory.read(addr);
          self.update_flags(dr);
          println!("LDR\tR{} R{} 0x{:X}", dr, base_reg, offset);
        },
        OpCode::LEA => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   dr   |        PCoffset9         |
          let dr = ((instr >> 9) & 0b111) as usize;
          let offset = sign_extend(instr & 0x1FF, 9);
          self.reg[dr] = self.reg[R_PC].wrapping_add(offset);
          self.update_flags(dr);
          println!("LEA\tR{} 0x{:X}", dr, offset);
        },
        OpCode::NOT => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   dr   |   sr   | 1|     11111    |
          let dr = ((instr >> 9) & 0b111) as usize;
          let sr = ((instr >> 6) & 0b111) as usize;
          self.reg[dr] = !self.reg[sr];
          self.update_flags(dr);
          println!("NOT\tR{} R{}", dr, sr);
        },
        OpCode::RTI => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |           000000000000            |

          /*
            if (PSR[15] == 0)
              PC = mem[R6]; R6 is the SSP
              R6 = R6+1;
              TEMP = mem[R6];
              R6 = R6+1;
              PSR = TEMP; the privilege mode and condition codes of
              the interrupted process are restored
            else
              Initiate a privilege mode exception;
          */
          println!("RTI\tinstruction not implemented. Aborting.");
          self.running = false;
        },
        OpCode::ST => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   sr   |        PCoffset9         |
          let sr = ((instr >> 9) & 0b111) as usize;
          let offset = sign_extend(instr & 0x1FF, 9);
          let addr = self.reg[R_PC].wrapping_add(offset) as usize;
          self.memory.write(addr, self.reg[sr]);
          println!("ST\tR{} 0x{:X}", sr, offset);
        },
        OpCode::STI => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   sr   |        PCoffset9         |
          let sr = ((instr >> 9) & 0b111) as usize;
          let offset = sign_extend(instr & 0x1FF, 9);
          let addr = self.reg[R_PC].wrapping_add(offset) as usize;
          let indirect_addr = self.memory.read(addr) as usize;
          self.memory.write(indirect_addr, self.reg[sr]);
          println!("STI\tR{} 0x{:X}", sr, offset);
        },
        OpCode::STR => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   sr   | baseR  |     offset6     |
          let sr = ((instr >> 9) & 0b111) as usize;
          let base_reg = ((instr >> 6) & 0b111) as usize;
          let offset = sign_extend(instr & 0x3F, 6);
          let addr = self.reg[base_reg].wrapping_add(offset) as usize;
          self.memory.write(addr, self.reg[sr]);
          println!("STR\tR{} R{} 0x{:X}", sr, base_reg, offset);
        },
        OpCode::TRAP => {
          // |15|14|13|12|11|10| 9| 8| 7| 6| 5| 4| 3| 2| 1| 0|
          // |  op code  |   0000    |       trapvect8       |
          let trapvect8 = (instr & 0xFF) as u8;
          print!("TRAP\t0x{:X}", trapvect8);
          let trap = TrapCode::from_trapvect8(trapvect8).unwrap();
          println!("\t{:?}", trap);
          self.execute_trap(trap);
        },
        OpCode::RES => {
          println!("RES instruction not implemented. Aborting.");
          self.running = false;
        }
      }
    }
  }

  fn update_flags(&mut self, reg: usize) {
    let reg_val = self.reg[reg];
    if reg_val == 0 {
      self.reg[R_COND] = FL_ZRO;
    } else if reg_val > 0 {
      self.reg[R_COND] = FL_POS;
    } else {
      self.reg[R_COND] = FL_NEG;
    }
  }

  fn execute_trap(&mut self, trap: TrapCode) {
    match trap {
      TrapCode::GETC => {
        // Read one ASCII char from keyboard and copy to R0,
        // clearing high eight bits of R0.
        let mut buf:[u8; 1] = [0];
        let size = std::io::stdin().read(&mut buf).unwrap();
        assert_eq!(size, 1);
        self.reg[R_R0] = (buf[0] as u16) & 0x00FF;
      },
      TrapCode::OUT => {
        let character = ((self.reg[R_R0] & 0x00FF) as u8) as char;
        print!("{}", character);
      },
      TrapCode::PUTS => {
        // Start with non-zero to enter loop
        let mut curr_addr = self.reg[R_R0] as usize;
        let mut next_char = self.memory.read(curr_addr);
        while next_char != 0x0000 {
          print!("{}", ((next_char & 0x00FF) as u8) as char);
          curr_addr += 1;
          next_char = self.memory.read(curr_addr);
        }
      },
      TrapCode::IN => {
        // Same as GETC, but prompt user on console and show result.
        print!("Press a key: ");
        let mut buf:[u8; 1] = [0];
        let size = std::io::stdin().read(&mut buf).unwrap();
        assert_eq!(size, 1);
        println!("{}", buf[0] as char);
        self.reg[R_R0] = (buf[0] as u16) & 0x00FF;
      },
      TrapCode::PUTSP => {
        // Same as PUTS, but characters are packed two per memory address.
        // |15 |7  |15 |7  |15 |7  |15 |7  |
        // | H | E | L | L | \0| O | \0| \0|
        //       *           *        *---- Terminates on 0x0000, same as PUTS
        //       |           |---- Odd lengths, last char is stored in low byte
        //       |---- Low byte is written first, then high byte.
        let mut curr_addr = self.reg[R_R0] as usize;
        let mut next_chars = self.memory.read(curr_addr);
        while next_chars != 0x0000 {
          print!("{}", ((next_chars & 0x00FF) as u8) as char);
          if next_chars > 0xFF {
            print!("{}", ((next_chars >> 8) as u8) as char);
          }
          curr_addr += 1;
          next_chars = self.memory.read(curr_addr);
        }
      },
      TrapCode::HALT => {
        self.running = false;
        println!("HALT");
      },
    }
  }
}
