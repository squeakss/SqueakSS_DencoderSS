use base64::{decode, encode};
use std::io::{self, Write};

fn main() {
    loop {
        println!();
        println!("Available options:");
        println!("1: Encode to Base64 from ASCII");
        println!("2: Decode from Base64 to ASCII");
        println!("3: Encode to Binary from ASCII");
        println!("4: Decode from Binary to ASCII");
        println!("5: Encode to Hex from ASCII");
        println!("6: Decode from Hex to ASCII");
        println!("Rot: Rotate a-z 1-25 times");
        println!("exit: Exit");
        println!();

        let mut choice = String::new();
        print!("Enter the number of the tool that you would like to use, or type exit: ");
        io::stdout().flush().unwrap(); // Ensure "Enter your choice: " is printed before reading input
        io::stdin().read_line(&mut choice).expect("Big dumdum...");

        match choice.trim() {
            "1" => {
                let input = read_input("Enter the ASCII string to encode to Base64: ");
                let encoded = encode(input);
                println_with_padding(&format!("Encoded: {}", encoded));
            }
            "2" => {
                let input = read_input("Enter the Base64 string to decode into ASCII: ");
                match decode(&input) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => println_with_padding(&format!("Decoded: {}", s)),
                        Err(_) => println_with_padding("Failed to convert bytes to ASCII string."),
                    },
                    Err(_) => println_with_padding("Failed to decode Base64."),
                }
            }
            "3" => {
                let input = read_input("Enter the ASCII string to encode to Binary: ");
                let binary_encoded = input
                    .bytes()
                    .map(|b| format!("{:08b}", b))
                    .collect::<Vec<String>>()
                    .join(" ");
                println_with_padding(&format!("Encoded to Binary: {}", binary_encoded));
            }
            "4" => {
                let input = read_input("Enter the Binary string to decode into ASCII: ");
                match binary_to_ascii(&input) {
                    Ok(decoded) => println_with_padding(&format!("Decoded to ASCII: {}", decoded)),
                    Err(e) => println_with_padding(&format!("Error: {}", e)),
                }
            }
            "5" => {
                let input = read_input("Enter the ASCII string to encode to Hex: ");
                let hex_encoded = ascii_to_hex(&input);
                println_with_padding(&format!("Encoded to Hex: {}", hex_encoded));
            }
            "6" => {
                let input = read_input("Enter the Hex string to decode into ASCII: ");
                match hex_to_ascii(&input) {
                    Ok(decoded) => println_with_padding(&format!("Decoded to ASCII: {}", decoded)),
                    Err(e) => println_with_padding(&format!("Error: {}", e)),
                }
            }
            "Rot" => {
                let mut ciphertext = String::new();
                println_with_padding("What's the string?");
                io::stdin()
                .read_line(&mut ciphertext)
                .expect("Failed to read line");
                ciphertext = ciphertext.trim_end().to_string();

                for shift in 1..=25 {
                let decrypted_message = Rotation(&ciphertext, shift);
                println!("Shift {}: {}", shift, decrypted_message);
                }
            }
            "exit" => {
                println_with_padding("Exiting...");
                break;
            }
            _ => println_with_padding("Yuh fuckin dummy."),
        }
    }
}

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap(); // Ensure the prompt is printed before reading input
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    input.trim().to_string()
}

fn println_with_padding(content: &str) {
    println!("\n{}\n", content);
}

fn binary_to_ascii(s: &str) -> Result<String, &'static str> {
    s.split(' ')
        .map(|byte_str| u8::from_str_radix(byte_str, 2))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "Failed to parse binary to ASCII")
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Failed to convert bytes to ASCII"))
}

fn hex_to_ascii(input: &str) -> Result<String, &'static str> {
    (0..input.len())
        .step_by(3) // Considering there's a space between each hex byte representation.
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "Failed to parse hex to ASCII")
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Failed to convert bytes to ASCII"))
}

fn ascii_to_hex(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|&b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" ")
}

fn Rotation(ciphertext: &str, shift: u8) -> String {
    ciphertext
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { 'a' } else { 'A' } as u8;
                let offset = c as u8 - first;
                let new_offset = (offset + (26 - shift) % 26) % 26;
                (first + new_offset) as char
            } else {
                c
            }
        })
        .collect()
}
