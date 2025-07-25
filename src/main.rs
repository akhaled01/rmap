use rmap::args::get_config;

fn main() {
    let config = get_config();
    println!("{:?}", config);
}
