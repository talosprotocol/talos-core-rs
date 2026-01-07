use std::env;
use talos_core_rs::adapters::crypto::RealCryptoProvider;
use talos_core_rs::domain::wallet::Wallet;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let command = &args[1];
    let provider = RealCryptoProvider;

    match command.as_str() {
        "gen-wallet" => {
            let name = args.get(2).cloned();
            let wallet = Wallet::generate(name.clone(), &provider);
            println!("Generated Wallet:");
            println!("  Name: {:?}", wallet.name());
            println!("  DID: {}", wallet.to_did());
            println!("  Address: {}", wallet.address(&provider));
            println!("  Public Key (hex): {}", hex::encode(wallet.public_key));
            println!("  Secret Key (hex): {}", hex::encode(wallet.secret_key));
        }
        "sign" => {
            if args.len() < 3 {
                println!("Usage: talos-cli sign <message> [--secret <hex_secret>]");
                return;
            }
            let message = &args[2];

            let mut secret_hex = None;
            for i in 3..args.len() {
                if args[i] == "--secret" && i + 1 < args.len() {
                    secret_hex = Some(&args[i + 1]);
                    break;
                }
            }

            let wallet = if let Some(hex_seed) = secret_hex {
                let seed_bytes = hex::decode(hex_seed).expect("Invalid hex secret");
                let seed: [u8; 32] = seed_bytes.try_into().expect("Secret must be 32 bytes");
                Wallet::from_seed(seed, Some("Restored from CLI".into()), &provider)
            } else {
                println!("Generating temporary wallet for signing...");
                Wallet::generate(Some("Demo signer".into()), &provider)
            };

            let sig = wallet.sign(message.as_bytes(), &provider);
            println!("Signing with: {:?}", wallet.name());
            println!("Message: {}", message);
            println!("Signature (hex): {}", hex::encode(sig));
            println!("Public Key (hex): {}", hex::encode(wallet.public_key));
            println!(
                "Verified: {}",
                Wallet::verify(message.as_bytes(), &sig, &wallet.public_key, &provider)
            );
        }
        _ => {
            print_usage();
        }
    }
}

fn print_usage() {
    println!("Talos Core CLI");
    println!("Usage:");
    println!("  talos-cli gen-wallet [name]");
    println!("  talos-cli sign <message> [--secret <hex_secret>]");
}
