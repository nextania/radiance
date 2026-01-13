use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, password_hash::rand_core::OsRng};
use clap::{Parser, Subcommand};
use radiance_types::{ControlCommand, ControlResponse};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

#[derive(Parser)]
#[command(name = "radiance-cli")]
#[command(about = "CLI tool to manage Radiance reverse proxy", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "/tmp/radiance.sock")]
    socket: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    ListHosts,
    GetHost {
        #[arg(short, long)]
        id: String,
    },
    Reload,
    HashPassword,
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run_command(&cli.socket, cli.command) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn send_command(
    socket_path: &str,
    command: ControlCommand,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(socket_path)?;
    let command_json = serde_json::to_string(&command)? + "\n";
    stream.write_all(command_json.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response: ControlResponse = serde_json::from_str(&line)?;
    match response {
        ControlResponse::Success { data } => Ok(data),
        ControlResponse::Error { error } => Err(Box::new(error)),
    }
}

fn run_command(socket_path: &str, command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::ListHosts => {
            let response = send_command(socket_path, ControlCommand::ListHosts)?;
            println!("✓ Hosts:");
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::GetHost { id } => {
            let response = send_command(socket_path, ControlCommand::GetHost { id })?;
            println!("✓ Host:");
            println!("{}", serde_json::to_string_pretty(&response)?);
        },
        Commands::Reload => {
            send_command(socket_path, ControlCommand::Reload)?;
            println!("✓ Reload command sent successfully");
        },
        Commands::HashPassword => {
            write!(std::io::stdout(), "Enter password: ")?;
            std::io::stdout().flush()?;
            let password = readpass::from_tty()?;
            let hashed = Argon2::default()
                .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                .map_err(|e| format!("Fail to hash password: {}", e))?
                .to_string();
            println!("✓ Hashed password: {}", hashed);
        }
    };

    Ok(())
}
