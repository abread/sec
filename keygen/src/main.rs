use std::{collections::HashMap, path::PathBuf};

use eyre::{eyre, Result, WrapErr};
use model::keys::{EntityId, EntityPrivComponent, KeyStore, Role};
use structopt::StructOpt;

const ENTITY_REGISTRY_PATH: &str = "entity_registry.json";

/// Key management utility.
#[derive(StructOpt)]
struct Options {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt)]
pub enum Command {
    /// Generates keystores for all entities in the HDLT system.
    /// Will store the private keys as <entity id>_privkeys.json and the entity
    /// registry as entity_registry.json in the current directory.
    GenerateKeys {
        /// User IDs to generate keystores for.
        #[structopt(short, long)]
        users: Vec<EntityId>,

        /// Server IDs to generate keystores for.
        #[structopt(short, long)]
        servers: Vec<EntityId>,

        /// Health Authority Client IDs to generate keystores for.
        #[structopt(short, long)]
        ha_clients: Vec<EntityId>,
    },

    /// Change password for private keys
    ChangePassword {
        /// Path to secret keys.
        #[structopt()]
        key_path: PathBuf,

        /// Current key password. Omit if there is none.
        #[structopt(long, short)]
        old_password: Option<String>,

        /// New key password. Omit to leave keys unprotected.
        #[structopt(long, short)]
        new_password: Option<String>,
    },
}

fn main() -> Result<()> {
    color_eyre::install()?;

    match Options::from_args().command {
        Command::GenerateKeys {
            users,
            servers,
            ha_clients,
        } => generate_keys(users, servers, ha_clients),
        Command::ChangePassword {
            key_path,
            old_password,
            new_password,
        } => change_password(key_path, old_password, new_password),
    }
}

fn change_password(
    key_path: PathBuf,
    old_password: Option<String>,
    new_password: Option<String>,
) -> Result<()> {
    let mut skeys = EntityPrivComponent::load_from_file(&key_path)?;

    if let Some(password) = old_password {
        skeys.unlock(&password)?;
    }

    if let Some(password) = new_password {
        skeys.lock(&password)?;
    }

    skeys.save_to_file(&key_path)?;

    println!("Done");

    Ok(())
}

fn generate_keys(
    users: Vec<EntityId>,
    servers: Vec<EntityId>,
    ha_clients: Vec<EntityId>,
) -> Result<()> {
    validate_gen_keys_options(&users, &servers, &ha_clients)?;

    // generate keys
    let mut privkeys = HashMap::new();
    for &id in &users {
        privkeys.insert(id, EntityPrivComponent::new(id, Role::User));
    }
    for &id in &servers {
        privkeys.insert(id, EntityPrivComponent::new(id, Role::Server));
    }
    for &id in &ha_clients {
        privkeys.insert(id, EntityPrivComponent::new(id, Role::HaClient));
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

fn validate_gen_keys_options(
    users: &[EntityId],
    servers: &[EntityId],
    ha_clients: &[EntityId],
) -> Result<()> {
    if let Some(id) = users.iter().find(|id| servers.contains(id)) {
        return Err(eyre!(
            "Entity {} cannot be a user and a server at the same time",
            id
        ));
    }
    if let Some(id) = users.iter().find(|id| ha_clients.contains(id)) {
        return Err(eyre!(
            "Entity {} cannot be a user and a HA client at the same time",
            id
        ));
    }
    if let Some(id) = servers.iter().find(|id| ha_clients.contains(id)) {
        return Err(eyre!(
            "Entity {} cannot be a server and a HA client at the same time",
            id
        ));
    }
    Ok(())
}
