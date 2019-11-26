use biscuit::crypto::KeyPair;
use biscuit::token::{builder::*, Biscuit};
use rand::prelude::*;

fn main() {
    let mut rng: StdRng = SeedableRng::seed_from_u64(1234);
    let root = KeyPair::new(&mut rng);
    println!("# Biscuit samples and expected results\n");
    println!(
        "root secret key: {}",
        hex::encode(root.private().to_bytes())
    );
    println!("root public key: {}", hex::encode(root.public().to_bytes()));

    topic_produce(&mut rng, &root);
    superuser(&mut rng, &root);
}

fn topic_produce<T: Rng + CryptoRng>(rng: &mut T, root: &KeyPair) {
    let mut builder = Biscuit::builder(rng, &root);
    builder.add_authority_fact(&fact(
        "right",
        &[s("authority"), s("topic"), string("public"), string("default"), string("test"), s("produce")],
    ));

    let biscuit1 = builder.build().unwrap();
    let data = biscuit1.to_vec().unwrap();
    println!("topic_produce({} bytes):", data.len());
    println!("{}", &biscuit1.print());
    println!("biscuit:{}", &b64(&data));
}

fn superuser<T: Rng + CryptoRng>(rng: &mut T, root: &KeyPair) {
    let mut builder = Biscuit::builder(rng, &root);
    builder.add_authority_fact(&fact(
        "right",
        &[s("authority"), s("admin")],
    ));

    let biscuit1 = builder.build().unwrap();
    let data = biscuit1.to_vec().unwrap();
    println!("superuser({} bytes):", data.len());
    println!("{}", &biscuit1.print());
    println!("biscuit:{}", &b64(&data));
}

fn b64(data: &[u8]) -> String {
  base64::encode_config(data, base64::URL_SAFE)
}

