use std::io::{self, Write};
use base64::{encode, decode};

fn main() {
    loop {
        println!("Available options:");
        println!("1: Encode to Base64 from ASCII");
        println!("2: Decode from Base64 to ASCII");
        println!("3: Exit");

        let mut choice = String::new();
        print!("Enter your choice: ");
        io::stdout().flush().unwrap(); // Ensure "Enter your choice: " is printed before reading input
        io::stdin().read_line(&mut choice).expect("Big dumdum...");

        match choice.trim() {
            "1" => {
                let input = read_input("Enter the ASCII string to encode to Base64: ");
                let encoded = encode(input);
                println_with_padding(&format!("Encoded: {}", encoded));
            },
            "2" => {
                let input = read_input("Enter the Base64 string to decode into ASCII: ");
                match decode(&input) {
                Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => println_with_padding(&format!("Decoded: {}", s)),
                Err(_) => println_with_padding("Failed to convert bytes to ASCII string."),
                                                            },
                Err(_) => println_with_padding("Failed to decode Base64."),
                                    }
                    },
            "3" => {
                println!("Exiting...");
                break;
                    },
            _ => println_with_padding("Yuh fuckin dummy."),
        }
    }
}

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap(); // Ensure the prompt is printed before reading input
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    input.trim().to_string()
}

fn println_with_padding(content: &str) {
    println!("\n{}\n", content);
}