use astrid_gateway::openapi::ApiDoc;
use std::io::Write;
use utoipa::OpenApi;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let doc = ApiDoc::openapi();
    let mut writer = std::io::BufWriter::new(std::io::stdout().lock());
    serde_json::to_writer_pretty(&mut writer, &doc)?;
    writeln!(writer)?;
    Ok(())
}
