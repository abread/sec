use std::collections::HashMap;

use eyre::{eyre, Result, WrapErr};
use model::keys::{EntityId, EntityPrivComponent, KeyStore, Role};
use structopt::StructOpt;

const ENTITY_REGISTRY_PATH: &str = "entity_registry.json";

/// Generates keystores for all entities in the HDLT system.
/// Will store the private keys as <entity id>_privkeys.json and the entity registry as entity_registry.json in the current directory.
#[derive(StructOpt)]
struct Options {
    /// User IDs to generate keystores for.
    #[structopt(short, long)]
    users: Vec<EntityId>,

    /// Server IDs to generate keystores for.
    #[structopt(short, long, default_value = "0")]
    servers: Vec<EntityId>,

    /// Health Authority Client IDs to generate keystores for.
    #[structopt(short, long)]
    ha_clients: Vec<EntityId>,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let options = Options::from_args();
    validate_options(&options)?;

    // generate keys
    let mut privkeys = HashMap::new();
    for id in &options.users {
        privkeys.insert(*id, EntityPrivComponent::new(*id, Role::User));
    }
    for id in &options.servers {
        privkeys.insert(*id, EntityPrivComponent::new(*id, Role::Server));
    }
    for id in &options.ha_clients {
        privkeys.insert(*id, EntityPrivComponent::new(*id, Role::HaClient));
    }

    // Create some template keystore
    let mut keystore = KeyStore::new(
        privkeys
            .values()
            .next()
            .expect("No keys to generate")
            .clone(),
    );
    for privkey in privkeys.values() {
        keystore
            .add_entity(privkey.pub_component())
            .wrap_err(format!("Failed to add entity {} to keystore", privkey.id))?;
    }

    // store keystore for each user
    for (id, privkeys) in privkeys.into_iter() {
        keystore
            .set_me(privkeys)
            .wrap_err(format!("Failed to transform keystore for entity {}", id))?;
        keystore
            .save_to_files(ENTITY_REGISTRY_PATH, format!("{}_privkeys.json", id))
            .wrap_err(format!("Failed to save keystore for entity {}", id))?;
    }

    Ok(())
}

fn validate_options(options: &Options) -> Result<()> {
    if let Some(id) = options.users.iter().find(|id| options.servers.contains(id)) {
        return Err(eyre!(
            "Entity {} cannot be a user and a server at the same time",
            id
        ));
    }
    if let Some(id) = options
        .users
        .iter()
        .find(|id| options.ha_clients.contains(id))
    {
        return Err(eyre!(
            "Entity {} cannot be a user and a HA client at the same time",
            id
        ));
    }
    if let Some(id) = options
        .servers
        .iter()
        .find(|id| options.ha_clients.contains(id))
    {
        return Err(eyre!(
            "Entity {} cannot be a server and a HA client at the same time",
            id
        ));
    }

    Ok(())
}
