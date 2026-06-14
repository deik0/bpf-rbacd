//! BPF RBAC Client CLI

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "bpf-rbac",
    about = "BPF RBAC Client - Request BPF operations from daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a BPF map via the daemon
    #[command(name = "create-map")]
    CreateMap {
        /// Map type (hash, array, lru_hash, ringbuf)
        #[arg(long = "type", value_name = "TYPE")]
        map_type: Option<String>,

        /// Map name
        #[arg(long, value_name = "NAME")]
        name: Option<String>,

        /// Key size in bytes
        #[arg(long, value_name = "BYTES")]
        key_size: Option<u32>,

        /// Value size in bytes
        #[arg(long, value_name = "BYTES")]
        value_size: Option<u32>,

        /// Maximum number of entries (default: 1024)
        #[arg(long, value_name = "N")]
        max_entries: Option<u32>,

        /// Positional arguments for backward compatibility.
        #[arg(trailing_var_arg = true, hide = true)]
        positional: Vec<String>,
    },

    /// Check if the BPF RBAC daemon is running
    Status,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateMap {
            map_type,
            name,
            key_size,
            value_size,
            max_entries,
            positional,
        } => {
            let (map_type, name, key_size, value_size, max_entries) = resolve_create_map_args(
                map_type,
                name,
                key_size,
                value_size,
                max_entries,
                &positional,
            )?;

            println!("Connecting to BPF RBAC daemon...");

            let mut client = bpf_rbacd::protocol::client::BpfRbacClient::connect()?;

            println!("Requesting map creation:");
            println!("  Type: {}", map_type);
            println!("  Name: {}", name);
            println!("  Key size: {} bytes", key_size);
            println!("  Value size: {} bytes", value_size);
            println!("  Max entries: {}", max_entries);

            let fd = client.create_map(&map_type, &name, key_size, value_size, max_entries)?;

            println!("\n✓ Success! BPF map created with FD: {}", fd);
            println!("\nYou can now use this FD to read/write map data.");
        }

        Commands::Status => match bpf_rbacd::protocol::client::BpfRbacClient::connect() {
            Ok(_) => println!("✓ BPF RBAC daemon is running"),
            Err(e) => println!("✗ Daemon not available: {}", e),
        },
    }

    Ok(())
}

/// Resolve create-map arguments from either flags or positional args.
///
/// Supports both:
///   bpf-rbac create-map --type hash --name foo --key-size 4 --value-size 8
///   bpf-rbac create-map hash foo 4 8 1024
fn resolve_create_map_args(
    map_type: Option<String>,
    name: Option<String>,
    key_size: Option<u32>,
    value_size: Option<u32>,
    max_entries: Option<u32>,
    positional: &[String],
) -> Result<(String, String, u32, u32, u32)> {
    let has_flags =
        map_type.is_some() || name.is_some() || key_size.is_some() || value_size.is_some();

    if has_flags {
        let map_type = map_type.ok_or_else(|| anyhow::anyhow!("--type is required"))?;
        let name = name.ok_or_else(|| anyhow::anyhow!("--name is required"))?;
        let key_size = key_size.ok_or_else(|| anyhow::anyhow!("--key-size is required"))?;
        let value_size = value_size.ok_or_else(|| anyhow::anyhow!("--value-size is required"))?;
        let max_entries = max_entries.unwrap_or(1024);
        Ok((map_type, name, key_size, value_size, max_entries))
    } else if positional.len() >= 4 {
        let map_type = positional[0].clone();
        let name = positional[1].clone();
        let key_size: u32 = positional[2].parse().map_err(|_| {
            anyhow::anyhow!("invalid key_size '{}': expected a number", positional[2])
        })?;
        let value_size: u32 = positional[3].parse().map_err(|_| {
            anyhow::anyhow!("invalid value_size '{}': expected a number", positional[3])
        })?;
        let max_entries: u32 = if positional.len() > 4 {
            positional[4].parse().map_err(|_| {
                anyhow::anyhow!("invalid max_entries '{}': expected a number", positional[4])
            })?
        } else {
            1024
        };
        Ok((map_type, name, key_size, value_size, max_entries))
    } else {
        anyhow::bail!(
            "Missing required arguments.\n\n\
             Usage:\n  \
             bpf-rbac create-map --type <TYPE> --name <NAME> --key-size <BYTES> --value-size <BYTES> [--max-entries <N>]\n  \
             bpf-rbac create-map <type> <name> <key_size> <value_size> [max_entries]\n\n\
             Examples:\n  \
             bpf-rbac create-map --type hash --name my_counters --key-size 4 --value-size 8 --max-entries 1024\n  \
             bpf-rbac create-map hash my_map 4 8 1024"
        );
    }
}
