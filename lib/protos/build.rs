use std::io::Result;

fn main() -> Result<()> {
    tonic_build::compile_protos("./src/util.proto")?;
    tonic_build::compile_protos("./src/hdlt.proto")?;
    tonic_build::compile_protos("./src/driver.proto")?;
    tonic_build::compile_protos("./src/witness.proto")?;
    Ok(())
}
