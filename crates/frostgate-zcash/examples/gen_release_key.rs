fn main() {
    use rand::rngs::OsRng;
    let key = frostgate_zcash::keys::ReleaseKey::generate(&mut OsRng).unwrap();
    key.save(std::path::Path::new("rehearsal/release-key.json"))
        .unwrap();
    let addr = frostgate_zcash::address::p2pkh_testnet(&key.public_key_compressed());
    println!("{addr}");
}
