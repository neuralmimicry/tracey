#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracey::init_tracing();
    tracey::loader::run_loader(std::env::args().collect()).await
}
