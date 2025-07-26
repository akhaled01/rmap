use std::error::Error;

/// The prober utility is used to perform banner grabbing and detailed service detection
/// for a list of ports. on a specified host and ports
pub struct Prober;

impl Prober {
    pub fn new() -> Prober {
        Prober
    }

    pub async fn exec(&self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}