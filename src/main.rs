use rmap::args::get_config;
use rmap::utils::ensure_probe;
use rmap::core::Scanner;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    ensure_probe()?;
    let config = get_config();
    let scanner = Scanner::new(config);
    scanner.exec().await?;
    Ok(())
}
