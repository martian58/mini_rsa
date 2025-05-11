use clap::{Arg, Command};
use rand::seq::IndexedRandom;
use std::fs::File;
use std::io::{Read, Write};

/// Finds the greatest common divisor (GCD) using the Euclidean algorithm.
fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// Finds the modular multiplicative inverse of `e` under modulo `phi`.
fn mod_inverse(e: u64, phi: u64) -> Option<u64> {
    let (mut t, mut new_t) = (0, 1);
    let (mut r, mut new_r) = (phi as i64, e as i64);

    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }

    if r > 1 {
        return None;
    }

    if t < 0 {
        t += phi as i64;
    }

    Some(t as u64)
}

/// Generates a pair of two-digit prime numbers randomly.
fn generate_primes() -> (u64, u64) {
    let primes: [u64; 21] = [
        11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    let mut rng: rand::prelude::ThreadRng = rand::rng();
    let p: u64 = *primes.choose(&mut rng).unwrap();
    let mut q: u64 = *primes.choose(&mut rng).unwrap();
    while q == p {
        q = *primes.choose(&mut rng).unwrap();
    }
    (p, q)
}

/// Generates RSA keys (public and private).
fn generate_keys() -> ((u64, u64), (u64, u64)) {
    let (p, q) = generate_primes();
    let n = p * q;
    let phi = (p - 1) * (q - 1);

    let mut e = 3;
    while gcd(e, phi) != 1 && e < phi {
        e += 2;
    }

    let d = mod_inverse(e, phi).expect("Failed to find modular inverse");
    ((e, n), (d, n))
}

/// Saves a key to a file in a human-readable format.
fn save_key_to_file(path: &str, key_type: &str, key: (u64, u64)) {
    let mut file = File::create(path).expect("Failed to create key file");
    writeln!(file, "-----BEGIN RSA {} KEY-----", key_type).unwrap();
    writeln!(file, "{} {}", key.0, key.1).unwrap();
    writeln!(file, "-----END RSA {} KEY-----", key_type).unwrap();
}

/// Loads a key from a file.
fn load_key_from_file(path: &str) -> (u64, u64) {
    let mut file = File::open(path).expect("Failed to open key file");
    let mut content = String::new();
    file.read_to_string(&mut content)
        .expect("Failed to read key file");

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() != 3 {
        panic!("Invalid key file format");
    }

    let key_parts: Vec<u64> = lines[1]
        .split_whitespace()
        .map(|part| part.parse().expect("Invalid key component"))
        .collect();

    if key_parts.len() != 2 {
        panic!("Invalid key file format");
    }

    (key_parts[0], key_parts[1])
}

/// Encrypts a file using the public key.
fn encrypt_file(input_path: &str, output_path: &str, public_key: (u64, u64)) {
    // Read the input file content
    let mut input_file = File::open(input_path).expect("Failed to open input file");
    let mut content = Vec::new();
    input_file
        .read_to_end(&mut content)
        .expect("Failed to read input file");

    // Encrypt the content
    let encrypted_content: Vec<String> = content
        .iter()
        .map(|&byte| {
            let encrypted_byte = modular_exponentiation(byte as u64, public_key.0, public_key.1);
            format!("{:x}", encrypted_byte) // Store as hexadecimal for readability
        })
        .collect();

    // Write the encrypted content to the output file
    let mut output_file = File::create(output_path).expect("Failed to create output file");
    writeln!(output_file, "{}", encrypted_content.join(" ")).expect("Failed to write to output file");
}

/// Decrypts a file using the private key.
fn decrypt_file(input_path: &str, output_path: &str, private_key: (u64, u64)) {
    // Read the input file content
    let mut input_file = File::open(input_path).expect("Failed to open input file");
    let mut content = String::new();
    input_file
        .read_to_string(&mut content)
        .expect("Failed to read input file");

    // Decrypt the content
    let encrypted_bytes: Vec<u64> = content
        .split_whitespace()
        .map(|hex| u64::from_str_radix(hex, 16).expect("Invalid encrypted data"))
        .collect();

    let decrypted_content: Vec<u8> = encrypted_bytes
        .iter()
        .map(|&byte| modular_exponentiation(byte, private_key.0, private_key.1) as u8)
        .collect();

    // Write the decrypted content to the output file
    let mut output_file = File::create(output_path).expect("Failed to create output file");
    output_file
        .write_all(&decrypted_content)
        .expect("Failed to write to output file");
}

/// Performs modular exponentiation: (base^exp) % modulus.
fn modular_exponentiation(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp /= 2;
        base = (base * base) % modulus;
    }
    result
}

fn main() {
    let matches = Command::new("Mini-RSA")
        .version("2.0")
        .author("martian58")
        .about("A mini RSA implementation for text and file encryption")
        .subcommand(
            Command::new("generate")
                .about("Generates RSA keys")
                .arg(
                    Arg::new("name")
                        .short('n')
                        .long("name")
                        .value_name("NAME")
                        .help("Base name for the key files")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("encrypt")
                .about("Encrypts a file using the public key")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .value_name("INPUT")
                        .help("File to encrypt")
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("OUTPUT")
                        .help("File to save the encrypted content")
                        .required(true),
                )
                .arg(
                    Arg::new("key")
                        .short('k')
                        .long("key")
                        .value_name("PUBLIC_KEY_FILE")
                        .help("Public key file")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts a file using the private key")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .value_name("INPUT")
                        .help("File to decrypt")
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("OUTPUT")
                        .help("File to save the decrypted content")
                        .required(true),
                )
                .arg(
                    Arg::new("key")
                        .short('k')
                        .long("key")
                        .value_name("PRIVATE_KEY_FILE")
                        .help("Private key file")
                        .required(true),
                ),
        )
        .get_matches();

    if let Some(generate_matches) = matches.subcommand_matches("generate") {
        let name = generate_matches.get_one::<String>("name").unwrap();
        let (public_key, private_key) = generate_keys();
        save_key_to_file(&format!("{}.pub", name), "PUBLIC", public_key);
        save_key_to_file(name, "PRIVATE", private_key);
        println!("Keys generated: {}.pub (public), {} (private)", name, name);
    } else if let Some(encrypt_matches) = matches.subcommand_matches("encrypt") {
        let input = encrypt_matches.get_one::<String>("input").unwrap();
        let output = encrypt_matches.get_one::<String>("output").unwrap();
        let key = encrypt_matches.get_one::<String>("key").unwrap();
        let public_key = load_key_from_file(key);
        encrypt_file(input, output, public_key);
        println!("File encrypted: {}", output);
    } else if let Some(decrypt_matches) = matches.subcommand_matches("decrypt") {
        let input = decrypt_matches.get_one::<String>("input").unwrap();
        let output = decrypt_matches.get_one::<String>("output").unwrap();
        let key = decrypt_matches.get_one::<String>("key").unwrap();
        let private_key = load_key_from_file(key);
        decrypt_file(input, output, private_key);
        println!("File decrypted: {}", output);
    }
}