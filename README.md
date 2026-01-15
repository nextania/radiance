# <img height="100" alt="Radiance" src="https://github.com/user-attachments/assets/8469add9-3c14-461b-919e-c37cf25ae002" />

A high-performance reverse proxy built with Cloudflare's Pingora framework in Rust.

> [!WARNING]
> This project is currently in active development. Many features are incomplete or experimental. Use at your own risk.

## Key features (in progress)
- High-performance reverse proxying using Pingora
- TCP and UDP transport proxying
- Automatic ACME certificate management 
- Vault-based secret management
- Secure tunneling for exposing ports behind NAT/firewalls
- Secure SSH access via web browsers
- Challenge security mechanisms 
- Route-based OIDC authentication
- Dynamic configuration via API and CLI (with hot reloading)
- Intuitive management panel

## Components of this project
- `radiance`: the main reverse proxy server built on Pingora.
- `radiance-api`: API server for managing Radiance programmatically.
- `radiance-cli`: command-line interface for managing Radiance configurations and operations.
- `radiance-outpost`: a lightweight QUIC tunnel client for secure connections to Radiance servers.
- `radiance-types`: shared types and data structures used across Radiance components.
- `zenith`: ACME certificate manager for automatic certificate issuance and renewal.

See also: [`radiance-panel`](https://github.com/nextania/radiance-panel) - a web-based management panel for Radiance that uses the API to provide an intuitive interface for configuration and monitoring.

## Configuration
TODO

## Containerization
TODO

## License
Radiance is licensed under the GNU Affero General Public License v3.0. See the [LICENSE](LICENSE) file for details.
Contributions are welcome! 
