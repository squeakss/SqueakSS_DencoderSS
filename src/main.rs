use base64::{decode, encode};
use std::fs;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::{thread, time};

fn main() {
    println!("                              _                       __");
    println!("                            /   \\                  /      \\ ");
    println!("                           '      \\              /          \\ ");
    println!("                          |       |Oo          o|            |");
    println!("                          `    \\  |OOOo......oOO|   /        |");
    println!("                           `    \\OOOOOOOOOOOOOOO\\//        /");
    println!("                             \\ _o\\OOOOOOOOOOOOOOOO//. ___ /");
    println!("                         ______OOOOOOOOOOOOOOOOOOOOOOOo.___");
    println!("                          --- OO'* `OOOOOOOOOO'*  `OOOOO--");
    println!("                              OO.   OOOOOOOOO'    .OOOOO o");
    println!("                              `OOOooOOOOOOOOOooooOOOOOO'OOOo");
    println!("                            .OO \"OOOOOOOOOOOOOOOOOOOO\"OOOOOOOo");
    println!("                        __ OOOOOO`OOOOOOOOOOOOOOOO\"OOOOOOOOOOOOo");
    println!("                       ___OOOOOOOO_\"OOOOOOOOOOO\"_OOOOOOOOOOOOOOOO");
    println!("                         OOOOO^OOOO0`(____)/\"OOOOOOOOOOOOO^OOOOOO");
    println!("                         OOOOO OO000/00000000000OOOOOOOO OOOOOO");
    println!("                         OOOOO O0000000000000000 ppppoooooOOOOOO");
    println!("                         `OOOOO 0000000000000000 QQQQ \"OOOOOOO\"");
    println!("                          o\"OOOO 000000000000000oooooOOoooooooO'");
    println!("                          OOo\"OOOO.00000000000000000000OOOOOOOO'");
    println!("                         OOOOOO QQQQ 0000000000000000000OOOOOOO");
    println!("                        OOOOOO00eeee00000000000000000000OOOOOOOO.");
    println!("                       OOOOOOOO000000000000000000000000OOOOOOOOOO");
    println!("                       OOOOOOOOO00000000000000000000000OOOOOOOOOO");
    println!("                       `OOOOOOOOO000000000000000000000OOOOOOOOOOO");
    println!("                         \"OOOOOOOO0000000000000000000OOOOOOOOOOO'");
    println!("                           \"OOOOOOO00000000000000000OOOOOOOOOO\"");
    println!("                .ooooOOOOOOOo\"OOOOOOO000000000000OOOOOOOOOOO\"");
    println!("              .OOO\"\"\"\"\"\"\"\"\"\".oOOOOOOOOOOOOOOOOOOOOOOOOOOOOo");
    println!("              OOO         QQQQO\"'                      `\"QQQQ");
    println!("              OOO                            ");
    println!("              `OOo.                          ");
    println!("                `\"OOOOOOOOOOOOoooooooo.      ");
    println!("                                              ");
    println!();
    println!(" __                        _     __  __        ___                         _               ");
    println!("/ _\\ __ _ _   _  ___  __ _| | __/ _\\/ _\\      /   \\___ _ __   ___ ___   __| | ___ _ __ ___   ___");
    println!("\\ \\ / _` | | | |/ _ \\/ _` | |/ /\\ \\ \\ \\      / /\\ / _ \\ '_ \\ / __/ _ \\ / _` |/ _ \\ '__/ __| / __|");
    println!("_\\ \\ (_| | |_| |  __/ (_| |   < _\\ \\_\\ \\    / /_//  __/ | | | (_| (_) | (_| |  __/ |  \\__ \\ \\__ \\");
    println!("\\__/\\__, |\\__,_|\\___|\\__,_|_|\\__\\__/\\__/___/___,'\\___|__| |_|\\___\\___/ \\__,_|\\___|_|  |___/ |___/");
    println!("       |_|                            |_____|                                              ");

    pause_with_delay();

    println!();
    println!("Input Types:");
    println!("s: String as input");
    println!("l: List as input");
    println!("-----------------------------");
    println!("Available Modules:");
    println!("1: ASCII to Base64");
    println!("2: Base64 to ASCII");
    println!("3: ASCII to Binary");
    println!("4: Binary to ASCII");
    println!("5: ASCII to Hex");
    println!("6: Hex to ASCII");
    println!("7: Binary to Hex");
    println!("8: Hex to Binary");
    println!("9: URL encode");
    println!("10: URL decode");
    println!("11: Charcode encode");
    println!("12: Charcode decode");
    println!("Rot: Rotate a-z 1-25 times");
    println!("-----------------------------");
    println!("help: Syntax example");
    println!("exit: Exit");
    println!();

    loop {
        let mut choice = String::new();
        print!("Enter the input type appended by the desired module:");
        io::stdout().flush().unwrap(); // Ensure "Enter your choice: " is printed before reading input
        io::stdin()
            .read_line(&mut choice)
            .expect("Failed to read input");

        match choice.trim() {
            "s1" => {
                println!();
                let input = read_input("Enter the ASCII string to encode to Base64: ");
                let encoded = encode(input);
                println_with_padding(&format!("Encoded: {}", encoded));
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s2" => {
                println!();
                let input = read_input("Enter the Base64 string to decode into ASCII: ");
                match decode(&input) {
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Ok(s) => println_with_padding(&format!("Decoded: {}", s)),
                        Err(_) => println_with_padding("Failed to convert bytes to ASCII string."),
                    },
                    Err(_) => println_with_padding("Failed to decode Base64."),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s3" => {
                println!();
                let input = read_input("Enter the ASCII string to encode to Binary: ");
                let binary_encoded = input
                    .bytes()
                    .map(|b| format!("{:08b}", b))
                    .collect::<Vec<String>>()
                    .join(" ");
                println_with_padding(&format!("Encoded to Binary: {}", binary_encoded));
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s4" => {
                println!();
                let input = read_input("Enter the Binary string to decode into ASCII: ");
                match binary_to_ascii(&input) {
                    Ok(decoded) => println_with_padding(&format!("Decoded to ASCII: {}", decoded)),
                    Err(e) => println_with_padding(&format!("Error: {}", e)),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s5" => {
                println!();
                let input = read_input("Enter the ASCII string to encode to Hex: ");
                match ascii_to_hex(&input) {
                    Ok(hex_encoded) => {
                        println_with_padding(&format!("Encoded to Hex: {}", hex_encoded))
                    }
                    Err(e) => println_with_padding(&format!("Error: {}", e)),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s6" => {
                println!();
                let input = read_input("Enter the Hex string to decode into ASCII: ");
                match hex_to_ascii(&input) {
                    Ok(decoded) => println_with_padding(&format!("Decoded: {}", decoded)),
                    Err(e) => println_with_padding(&format!("Error: {}", e)),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s7" => {
                println!();
                let input = read_input("Enter the Binary string to decode into Hex: ");
                match binary_to_hex(&input) {
                    Ok(hex_decoded) => {
                        println_with_padding(&format!("Decoded to Hex: {}", hex_decoded))
                    }
                    Err(e) => println_with_padding(&format!("Error: {}", e)),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s8" => {
                println!();
                let input = read_input("Enter the Hex string to encode to Binary: ");
                match hex_to_binary(&input) {
                    Ok(binary_encoded) => {
                        println_with_padding(&format!("Encoded to Binary: {}", binary_encoded))
                    }
                    Err(e) => println_with_padding(&format!("Error: {}", e)),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s9" => {
                println!();
                let input = read_input("Enter the string to URL encode: ");
                println!();
                match url_encode(&input) {
                    Ok(encoded) => println!("Encoded URL: {}", encoded),
                    Err(e) => println!("Error: {}", e),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s10" => {
                println!();
                let input = read_input("Enter the URL-encoded string to decode: ");
                println!();
                match url_decode(&input) {
                    Ok(decoded) => println!("Decoded URL: {}", decoded),
                    Err(err) => println!("Error decoding URL: {}", err),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s11" => {
                println!();
                let input = read_input("Enter the string to convert to charcodes: ");
                println!();
                match string_to_charcodes(&input) {
                    Ok(charcodes) => println!("Charcodes: {}", charcodes),
                    Err(e) => println!("Error: {}", e),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "s12" => {
                println!();
                let input = read_input("Enter charcodes to convert to string: ");
                println!();
                match charcodes_to_string(&input) {
                    Ok(string) => println!("String: {}", string),
                    Err(e) => println!("Error: {}", e),
                }
                println!("___________________________________________________________________________________________");
                println!();
            }
            "l1" => process_file_module("Enter the file path:", ascii_to_base64),
            "l2" => process_file_module("Enter the file path:", base64_to_ascii),
            "l3" => process_file_module("Enter the file path:", ascii_to_binary),
            "l4" => process_file_module("Enter the file path:", binary_to_ascii_wrapper),
            "l5" => process_file_module("Enter the file path:", ascii_to_hex),
            "l6" => process_file_module("Enter the file path:", hex_to_ascii_wrapper),
            "l7" => process_file_module("Enter the file path:", binary_to_hex_wrapper),
            "l8" => process_file_module("Enter the file path:", hex_to_binary_wrapper),
            "l9" => process_file_module("Enter the file path:", url_encode),
            "l10" => process_file_module("Enter the file path:", url_decode_wrapper),
            "l11" => process_file_module("Enter the file path:", string_to_charcodes),
            "l12" => process_file_module("Enter the file path:", charcodes_to_string_wrapper),
            "exit" => {
                println!();
                println_with_padding("Exiting...");
                break;
            }
            _ => println_with_padding("Invalid choice. Please try again."),
        }
    }
}

fn pause_with_delay() {
    let pause_time = time::Duration::from_secs(3); // x seconds
    thread::sleep(pause_time);
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

fn process_file_module<F>(prompt: &str, process_line: F)
where
    F: Fn(&str) -> Result<String, &'static str>,
{
    println!("{}", prompt);
    let mut path = String::new();
    io::stdin()
        .read_line(&mut path)
        .expect("Failed to read path");
    let path = Path::new(path.trim());

    if let Err(e) = process_file_lines(path, process_line) {
        println!("Error processing file: {}", e);
    }
    println!("___________________________________________________________________________________________");
    println!();
}

fn process_file_lines<F>(input_path: &Path, process_line: F) -> io::Result<()>
where
    F: Fn(&str) -> Result<String, &'static str>,
{
    let input_file = File::open(input_path)?;
    let reader = BufReader::new(input_file);

    println!("Do you want to save the results to a file? (yes/no)");
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;

    let output_method = answer.trim().to_lowercase();

    let mut output_file = if output_method == "yes" {
        println!("Enter the output file path:");
        let mut output_path = String::new();
        io::stdin().read_line(&mut output_path)?;
        Some(File::create(output_path.trim())?)
    } else {
        None
    };

    for line in reader.lines() {
        let line = line?;
        match process_line(&line) {
            Ok(result) => {
                if let Some(file) = output_file.as_mut() {
                    writeln!(file, "{}: {}", line, result)?;
                } else {
                    println!("{}: {}", line, result);
                }
            }
            Err(e) => {
                if let Some(file) = output_file.as_mut() {
                    writeln!(file, "Error processing line '{}': {}", line, e)?;
                } else {
                    println!("Error processing line '{}': {}", line, e);
                }
            }
        }
    }

    Ok(())
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

fn binary_to_ascii_wrapper(s: &str) -> Result<String, &'static str> {
    binary_to_ascii(s).map_err(|_| "Failed to convert binary to ASCII")
}

fn hex_to_ascii(input: &str) -> Result<String, &'static str> {
    input
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "Failed to parse hex to ASCII")
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Failed to convert bytes to ASCII"))
}

fn hex_to_ascii_wrapper(input: &str) -> Result<String, &'static str> {
    hex_to_ascii(input).map_err(|_| "Failed to convert hex to ASCII")
}

fn binary_to_hex(input: &str) -> Result<String, &'static str> {
    input
        .split(' ')
        .map(|byte_str| u8::from_str_radix(byte_str, 2))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "Invalid binary digit")
        .map(|bytes| {
            bytes
                .iter()
                .map(|&b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join(" ")
        })
}

fn binary_to_hex_wrapper(input: &str) -> Result<String, &'static str> {
    binary_to_hex(input).map_err(|_| "Failed to convert binary to hex")
}

fn hex_to_binary(input: &str) -> Result<String, &'static str> {
    input
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "Invalid hex digit")
        .map(|bytes| {
            bytes
                .iter()
                .map(|&b| format!("{:08b}", b))
                .collect::<Vec<String>>()
                .join(" ")
        })
}

fn hex_to_binary_wrapper(input: &str) -> Result<String, &'static str> {
    hex_to_binary(input).map_err(|_| "Failed to convert hex to binary")
}

fn ascii_to_hex(input: &str) -> Result<String, &'static str> {
    Ok(input
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(" "))
}

fn ascii_to_binary(input: &str) -> Result<String, &'static str> {
    Ok(input
        .bytes()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<String>>()
        .join(" "))
}

fn ascii_to_base64(input: &str) -> Result<String, &'static str> {
    Ok(encode(input))
}

fn base64_to_ascii(input: &str) -> Result<String, &'static str> {
    decode(input)
        .map_err(|_| "Failed to decode Base64")
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Failed to convert bytes to ASCII"))
}

fn url_encode(input: &str) -> Result<String, &'static str> {
    Ok(urlencoding::encode(input).to_string())
}

fn url_decode(input: &str) -> Result<String, &'static str> {
    urlencoding::decode(input).map_err(|_| "Failed to decode URL")
}

fn url_decode_wrapper(input: &str) -> Result<String, &'static str> {
    url_decode(input).map_err(|_| "Failed to decode URL")
}

fn string_to_charcodes(input: &str) -> Result<String, &'static str> {
    Ok(input
        .chars()
        .map(|c| c as u32) // Convert char to Unicode code point
        .map(|code| code.to_string())
        .collect::<Vec<String>>()
        .join(" "))
}

fn charcodes_to_string(input: &str) -> Result<String, &'static str> {
    input
        .split_whitespace()
        .map(|code| {
            code.parse::<u32>()
                .map_err(|_| "Invalid input".to_string())
                .and_then(|code| {
                    std::char::from_u32(code).ok_or_else(|| "Invalid charcode".to_string())
                })
        })
        .collect::<Result<String, String>>()
        .map_err(|_| "Failed to convert charcodes to string")
}

fn charcodes_to_string_wrapper(input: &str) -> Result<String, &'static str> {
    charcodes_to_string(input).map_err(|_| "Failed to convert charcodes to string")
}
