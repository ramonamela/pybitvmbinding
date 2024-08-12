use bitcoin::p2p::message;
use bitcoin_script_stack::stack::StackTracker;
use bitcoin_script_stack::interactive::interactive;
use sha2::{digest::typenum::Length, Digest as ShaDigest, Sha256};
use ripemd::Ripemd160;


pub fn compute_max_checksum(d0: u32, n0: u32, bits_per_digit_checksum: u32) -> (u32, u32, u32) {
    let max_checksum_value: u32 = n0 * (d0 - 1);
    let max_checksum_binary_representation = format!("{:b}", max_checksum_value);
    let current_length = max_checksum_binary_representation.len() as u32;
    let n1: u32;
    if current_length % bits_per_digit_checksum == 0 {
        n1 = current_length;
    } else {
        n1 = current_length / bits_per_digit_checksum + 1;
    }
    let d1: u32 = 2_u32.pow(bits_per_digit_checksum);
    return (d1, n1, max_checksum_value);
}

pub fn hash_160(input: &str) -> String {
    let sha256_hash = Sha256::digest(hex::decode(input).expect("Invalid hex string"));
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);
    let hash160_result = format!("{:x}", ripemd160_hash);
    hash160_result
}

pub fn derived_secret_key(secret_key: &str, i: u32) -> String {
    let hex_i = format!("{:02x}", i);
    let concatenated_key = format!("{}{}", secret_key, hex_i);
    let concatenated_key_bytes = hex::decode(concatenated_key).expect("Invalid hex string");
    let vec_derived_secret_key = Ripemd160::digest(&concatenated_key_bytes).to_vec();
    hex::encode(vec_derived_secret_key)
}

pub fn generate_winternitz_key_arrays(secret_key: &str, n0: u32, bits_per_digit_checksum: u32, gap: u32) -> Vec<Vec<String>> {
    let d0: u32 = 2_u32.pow(bits_per_digit_checksum);
    let (d1, n1, _) = compute_max_checksum(d0, n0, bits_per_digit_checksum);
    let mut winternitz_keys = Vec::new();
    for i in 0..n0 {
        let derived_key = derived_secret_key(secret_key, i);
        let mut current_array = Vec::new();
        let mut winternitz_key = format!("{}", derived_key);
        current_array.push(winternitz_key.clone());
        for _ in 0..d0 {
            winternitz_key = hash_160(winternitz_key.as_str());
            current_array.push(winternitz_key.clone());
        }
        winternitz_keys.push(current_array);
    }
    for i in 0..n1 {
        let derived_key = derived_secret_key(secret_key, n0 + i);
        let mut current_array = Vec::new();
        let mut winternitz_key = format!("{}", derived_key);
        current_array.push(winternitz_key.clone());
        for _ in 0..d1 {
            winternitz_key = hash_160(winternitz_key.as_str());
            current_array.push(winternitz_key.clone());
        }
        winternitz_keys.push(current_array);
    }
    winternitz_keys
}


pub fn generate_keys_nibbles(secret_key: &str, n0: u32, bits_per_digit_checksum: u32, gap: u32) -> Vec<String> {
    let mut public_keys: Vec<String> = Vec::new();
    let message_winternitz_keys = generate_winternitz_key_arrays(secret_key, n0, bits_per_digit_checksum, gap);
    for key_array in message_winternitz_keys {
        if let Some(last_key) = key_array.last() {
            public_keys.push(last_key.clone());
        }
    }
    public_keys
}

pub fn generate_witness_nibbles(private_key: &str, message: &str, d0: u32, bits_per_digit_checksum: u32, gap: u32) -> Vec<(u32, String)> {
    let mut witness: Vec<(u32, String)> = Vec::new();
    let message_digits: Vec<u32> = message.chars().map(|c| c.to_digit(16).unwrap_or(0)).collect();
    let n0: u32 = message_digits.len() as u32;
    let (d1, n1, max_checksum_value) = compute_max_checksum(d0, n0, bits_per_digit_checksum);
    let mut amount_of_hashes = 0;
    for (i, digit) in message_digits.iter().enumerate() {
        let mut current_private_key: String = derived_secret_key(private_key, i as u32);
        let current_digit: u32 = *digit;
        for _ in 0..current_digit {
            current_private_key = hash_160(current_private_key.as_str());
            amount_of_hashes += 1;
        }
        witness.push((current_digit, current_private_key));
    }
    let checksum_value_hex: String = format!("{:0width$x}", max_checksum_value - amount_of_hashes, width = n1 as usize);
    for (i, digit) in checksum_value_hex.chars().enumerate() {
        let current_digit: u32 = digit.to_digit(16).unwrap_or(0);
        let mut current_private_key: String = derived_secret_key(private_key, i as u32 + n0);
        for _ in 0..current_digit {
            current_private_key = hash_160(current_private_key.as_str());
            amount_of_hashes += 1;
        }
        witness.push((current_digit, current_private_key));
    }
    witness
}


pub fn verify_digit_signature_nibbles(mut script: StackTracker, public_key: &String, d: u32) -> StackTracker {
    script.number(d - 1);
    script.op_min();
    script.op_dup();
    script.to_altstack();
    script.to_altstack();
    for _ in 0..d {
        script.op_dup();
        script.op_hash160();
    }
    script.from_altstack();
    script.op_pick();
    script.hexstr(&public_key);
    script.op_equalverify();
    for _ in 0..d/2 {
        script.op_2drop();
    }
    script.op_drop();
    script
}


pub fn verify_checksum_nibbles(mut script: StackTracker, n0: u32, n1: u32, d1: u32, max_checksum_value: u32) -> StackTracker {
    script.from_altstack();
    script.op_dup();
    script.op_negate();
    for _ in 0..n0-1 {
        script.from_altstack();
        script.op_tuck();
        script.op_sub();
    }
    script.number(max_checksum_value);
    script.op_add();
    for i in (0..n1).rev() {
        script.from_altstack();
        for _ in 0..((d1 as f32).log2() as u32 * i) {
            script.op_dup();
            script.op_add();
        }
        if i < (n1 - 1) {
            script.op_add();
        }
    }
    script.op_equalverify();
    script
}


pub fn verify_input_nibbles(mut script: StackTracker, public_keys: Vec<String>, d: u32, n0: u32, bits_per_digit_checksum: u32) -> StackTracker {
    for public_key in public_keys.iter().rev() {
        script = verify_digit_signature_nibbles(script, public_key, d);
    }
    let (d1, n1, max_checksum_value) = compute_max_checksum(d, n0, bits_per_digit_checksum);
    script = verify_checksum_nibbles(script, n0, n1, d1,max_checksum_value);
    script
}

pub fn main() {
    let mut stack = StackTracker::new();
    let private_key: &str = "583d982939949f844a0cfd3521c7cba6de9bb9b6d7c00668805674bb30091f51";
    let message: &str = "deadbeafdeadbeafdeadbeafdeadbeafdeadbeafdeadbeafdeadbeafdead";
    let bits_per_digit_message: u32 = 4;
    let bits_per_digit_checksum: u32 = 4;
    let d0: u32 = 2_u32.pow(bits_per_digit_message);
    let d1: u32 = 2_u32.pow(bits_per_digit_checksum);
    let n0: u32 = message.len() as u32;
    let gap: u32 = 0;
    let public_keys = generate_keys_nibbles(private_key, n0, bits_per_digit_checksum, gap);
    let generate_witness: Vec<(u32, String)> = generate_witness_nibbles(private_key, message, d0, bits_per_digit_checksum, 0);
    for (i, private_hash) in generate_witness.iter() {
        println!("Witness: {} Value: {} Lenght: {}", private_hash, i, private_hash.len());
        stack.hexstr(private_hash);
        stack.number(*i);
    }
    stack.debug();
    assert_eq!(d0, d1, "d0 must be equal to d1");
    stack = verify_input_nibbles(stack, public_keys, d0, n0, bits_per_digit_checksum);
    for _ in 0..message.len() {
        stack.op_drop();
    }
/*     for public_key in public_keys.iter().rev() {
        println!("Public Key: {}", public_key);
        stack = verify_digit_signature(stack, public_key.clone(), d0);
    } */
    //stack.op_sha256();
    stack.op_true();
    stack.debug();
    assert!(stack.run().success);
    // interactive(&stack);
}

