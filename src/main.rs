use rmap::{args::get_config, core::Scanner};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = get_config();
    let scanner = Scanner::new(config);
    scanner.exec().await?;
    Ok(())
}
