use std::{io::BufReader, path::PathBuf};

use clap::{Arg, ArgAction, Command};

use converter::{
    config::{Config, LoadedConfig},
    converter::etsi_to_skip_converter,
    etsi014::Etsi014Server,
    skip::SkipClient,
};
use tokio::{sync::mpsc, task::JoinSet};
use tracing_subscriber::layer::SubscriberExt;

type AResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Main function for CLI
#[tokio::main]
async fn main() -> AResult<()> {
    // Set up tracing for event logging
    let subscriber = tracing_subscriber::registry().with(tracing_subscriber::fmt::layer());
    tracing::subscriber::set_global_default(subscriber)?;

    let matches = Command::new("QKD ETSI 014 to CISCO SKIP converter CLI")
        .about("Convert the QKD ETSI 014 KME request to a CISCO SKIP request by running a converter on both ends.")
        .arg(
            Arg::new("config")
                .long("config")
                .value_name("FILE")
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(PathBuf))
                .required(true),
        )
        .get_matches();

    // Read and parse the config file
    let config_path = matches.get_one::<PathBuf>("config").unwrap();
    let file = std::fs::File::open(&config_path).map_err(|err| format!("Error while opening '{}': '{}'", config_path.display(), err))?;
    let reader = BufReader::new(file);
    let conf: Result<Config, serde_yaml::Error> = serde_yaml::from_reader(reader);
    let raw_config = match conf {
        Ok(config) => config,
        Err(e) => {
            Err(format!("Problem while parsing config file: {}", e))?;
            unreachable!()
        }
    };
    // Load the files pointed to by the config file
    let LoadedConfig {
        skip_client,
        etsi_server,
        converter,
    } = raw_config.load()?;

    let skip_client = SkipClient::new(skip_client.address, skip_client.auth).await?;

    let (tx, rx) = mpsc::channel(8);

    let _converter_handle = tokio::spawn(etsi_to_skip_converter(rx, skip_client, etsi_server.sae_ids.clone(), converter));

    let server = Etsi014Server::new(etsi_server, tx).await?;

    let mut connections = JoinSet::new();

    loop {
        let conn_server = server.accept().await?;
        connections.spawn(conn_server);
    }
}
