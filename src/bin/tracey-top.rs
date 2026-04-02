fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracey::dashboard::run_tracey_top(std::env::args().collect())
}
