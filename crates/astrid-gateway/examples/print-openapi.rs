use astrid_gateway::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let doc = ApiDoc::openapi();
    serde_json::to_writer_pretty(std::io::stdout(), &doc)?;
    println!();
    Ok(())
}
