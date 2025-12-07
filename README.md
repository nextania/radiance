# Zenith

Zenith is a service that automatically requests and renews SSL/TLS certificates from Let's Encrypt using the ACME protocol and Cloudflare DNS-01 challenges.

## Configuration

Set the environment variables or use a `.env` file. 

- `CLOUDFLARE_API_KEY` - A Cloudflare API key with access to DNS for the applicable domains 
- `DOMAINS` - Comma-separated list of domains to generate certificates for
- `ACME_EMAIL` - Email for ACME account registration
- `USE_PRODUCTION` - Set to `true` to use the Let's Encrypt production environment
- `OUTPUT_DIR` - Directory to save certificates (default: `./certs`)
