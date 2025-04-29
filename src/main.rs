use clap::{Arg, Command};
use rand;
use rand::prelude::IndexedRandom;


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
    // Convert inputs to i64 for signed arithmetic
    let e_i64: i64 = e as i64;
    let phi_i64: i64 = phi as i64;
    
    let mut t: i64 = 0;
    let mut new_t: i64 = 1;
    let mut r: i64 = phi_i64;
    let mut new_r: i64 = e_i64;

    while new_r != 0 {
        let quotient: i64 = r / new_r;
        let (old_t, old_r) = (t, r);
        t = new_t;
        r = new_r;
        new_t = old_t - quotient * new_t;
        new_r = old_r - quotient * new_r;
    }

    if r > 1 {
        return None; // No modular inverse exists
    }
    if t < 0 {
        t += phi_i64;
    }
    // Convert back to u64 for the return value
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
    let n: u64 = p * q;
    let phi: u64 = (p - 1) * (q - 1);

    // Choose e such that 1 < e < phi and gcd(e, phi) = 1
    let mut e: u64 = 3; // Start with a small prime
    while gcd(e, phi) != 1 && e < phi {
        e += 2; // Increment by 2 to ensure e remains odd
    }

    // Calculate d as the modular multiplicative inverse of e modulo phi
    let d: u64 = mod_inverse(e, phi).expect("Failed to find modular inverse");

    ((e, n), (d, n))
}

/// Encrypts a plaintext message using the public key.
fn encrypt(plaintext: u64, public_key: (u64, u64)) -> u64 {
    let (e, n) = public_key;
    modular_exponentiation(plaintext, e, n)
}

/// Decrypts an encrypted message using the private key.
fn decrypt(ciphertext: u64, private_key: (u64, u64)) -> u64 {
    let (d, n) = private_key;
    modular_exponentiation(ciphertext, d, n)
}

/// Performs modular exponentiation: (base^exp) % modulus.
fn modular_exponentiation(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result: u64 = 1;
    let mut base: u64 = base % modulus;
    let mut exp: u64 = exp;

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
        .version("1.0")
        .author("martian58")
        .about("A mini RSA implementation using two-digit prime numbers")
        .subcommand(
            Command::new("generate")
                .about("Generates RSA keys (public and private)"),
        )
        .subcommand(
            Command::new("encrypt")
                .about("Encrypts a plaintext number using the public key")
                .arg(
                    Arg::new("plaintext")
                        .short('p')
                        .long("plaintext")
                        .value_name("PLAINTEXT")
                        .help("The plaintext number to encrypt")
                        .required(true),
                )
                .arg(
                    Arg::new("public_key")
                        .short('k')
                        .long("public_key")
                        .value_name("PUBLIC_KEY")
                        .help("The public key in the format e,n (e.g., 7,77)")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts a ciphertext number using the private key")
                .arg(
                    Arg::new("ciphertext")
                        .short('c')
                        .long("ciphertext")
                        .value_name("CIPHERTEXT")
                        .help("The ciphertext number to decrypt")
                        .required(true),
                )
                .arg(
                    Arg::new("private_key")
                        .short('k')
                        .long("private_key")
                        .value_name("PRIVATE_KEY")
                        .help("The private key in the format d,n (e.g., 23,77)")
                        .required(true),
                ),
        )
        .get_matches();

    if let Some(_) = matches.subcommand_matches("generate") {
        let (public_key, private_key) = generate_keys();
        println!("Public Key: {},{}", public_key.0, public_key.1);
        println!("Private Key: {},{}", private_key.0, private_key.1);
    } else if let Some(encrypt_matches) = matches.subcommand_matches("encrypt") {
        let plaintext: u64 = encrypt_matches
            .get_one::<String>("plaintext")
            .unwrap()
            .parse()
            .expect("Invalid plaintext number");
        let public_key: (u64, u64) = parse_key(
            encrypt_matches
                .get_one::<String>("public_key")
                .unwrap(),
        );
        let ciphertext: u64 = encrypt(plaintext, public_key);
        println!("Ciphertext: {}", ciphertext);
    } else if let Some(decrypt_matches) = matches.subcommand_matches("decrypt") {
        let ciphertext: u64 = decrypt_matches
            .get_one::<String>("ciphertext")
            .unwrap()
            .parse()
            .expect("Invalid ciphertext number");
        let private_key: (u64, u64) = parse_key(
            decrypt_matches
                .get_one::<String>("private_key")
                .unwrap(),
        );
        let plaintext: u64 = decrypt(ciphertext, private_key);
        println!("Plaintext: {}", plaintext);
    }
}

/// Helper function to parse a key from the format "e,n" or "d,n".
fn parse_key(key: &str) -> (u64, u64) {
    let parts: Vec<&str> = key.split(',').collect();
    if parts.len() != 2 {
        panic!("Invalid key format. Expected format: e,n or d,n");
    }
    let part1 = parts[0].parse().expect("Invalid key component");
    let part2 = parts[1].parse().expect("Invalid key component");
    (part1, part2)
}