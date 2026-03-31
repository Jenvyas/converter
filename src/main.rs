use std::{net::SocketAddrV4, path::PathBuf};

use clap::{Arg, ArgAction, Command};

use converter::{
    etsi014::Etsi014Server,
    peer::PeerConverter,
    skip::{SkipAuth, SkipClient},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Main function for CLI
#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("QKD ETSI 014 to CISCO SKIP converter CLI")
        .about("Convert the QKD ETSI 014 KME protocol to the CISCO SKIP by running the converter on both ends.")
        .arg(Arg::new("kme-addr").long("kme-addr").value_name("ADDR").action(ArgAction::Set).value_parser(clap::value_parser!(SocketAddrV4)).required(true))
        .arg(Arg::new("kme-crt").long("kme-crt").value_name("FILE_PATH").action(ArgAction::Set).value_parser(clap::value_parser!(PathBuf)).required(true)
            .conflicts_with_all(["kme-psk", "kme-psk-id"]))
        .arg(Arg::new("kme-psk").long("kme-psk").value_name("VALUE").action(ArgAction::Set).value_parser(clap::value_parser!(Vec<u8>)).required(true))
        .arg(Arg::new("kme-psk-id").long("kme-psk-id").value_name("VALUE").action(ArgAction::Set).value_parser(clap::value_parser!(Vec<u8>)).required(true))
        .arg(Arg::new("sae-addr").long("sae-addr").value_name("ADDR").action(ArgAction::Set).value_parser(clap::value_parser!(SocketAddrV4)).required(true))
        .arg(Arg::new("sae-id").long("sae-id").value_name("VALUE").action(ArgAction::Set).value_parser(clap::value_parser!(String)).required(true))
        .arg(Arg::new("sae-crt").long("sae-crt").value_name("FILE_PATH").action(ArgAction::Set).value_parser(clap::value_parser!(PathBuf)).required(true))
        .arg(Arg::new("converter-addr").long("converter-addr").value_name("ADDR").action(ArgAction::Set).value_parser(clap::value_parser!(SocketAddrV4)).required(true))
        .arg(Arg::new("converter-crt").long("converter-crt").value_name("FILE_PATH").action(ArgAction::Set).value_parser(clap::value_parser!(PathBuf)).required(true))
        .arg(Arg::new("converter-key").long("converter-key").value_name("FILE_PATH").action(ArgAction::Set).value_parser(clap::value_parser!(PathBuf)).required(true))
        .arg(Arg::new("converter-cert-authority").long("cert-authority").value_name("FILE_PATH").action(ArgAction::Set).value_parser(clap::value_parser!(PathBuf)).required(true))
        .arg(Arg::new("peer-cert-authority").long("peer-cert-authority").value_name("FILE_PATH").action(ArgAction::Set).value_parser(clap::value_parser!(PathBuf)).required(true))
        .arg(Arg::new("peer-addr").long("remote-addr").value_name("ADDR").action(ArgAction::Set).value_parser(clap::value_parser!(SocketAddrV4)).required(false))
        .get_matches();

    let kme_crt = matches.get_one::<PathBuf>("kme-crt");
    let kme_psk = matches.get_one::<Vec<u8>>("kme-psk");
    let kme_psk_id = matches.get_one::<Vec<u8>>("kme-psk-id");

    let skip_kme_auth = match (kme_crt, (kme_psk_id, kme_psk)) {
        (Some(crt_path), _) => SkipAuth::CaCrt(crt_path.to_owned()),
        (_, (Some(psk_id), Some(psk))) => SkipAuth::Psk(psk_id.to_owned(), psk.to_owned()),
        _ => unreachable!(),
    };

    let skip_kme_addr = matches.get_one::<SocketAddrV4>("kme-addr").unwrap();

    let mut skip_client = SkipClient::new(skip_kme_addr.to_owned(), skip_kme_auth).await?;

    let capabilities = skip_client.fetch_capabilities().await?;

    Ok(())
}
