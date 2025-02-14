# Telemetry Server

This telemetry server accepts Hedera CLI commands and stores them for analysis to improve the product and user experience. We don't store any personal information like command parameters, options, or keys. Just the command name and the time it was executed, like `account create` or `network use`, no further details.

Visit [Hedera CLI](https://github.com/hashgraph/hedera-cli) for more information.

## Usage

To start the server:

```bash
node server.js
```

You can now submit telemetry data to the server by sending a POST request to `http://localhost:3000/track` with the following JSON body:

```json
{
  "command": "account create", // command name from list of accepted commands
  "timestamp": "2021-08-01T12:00:00Z" // ISO date string
}
```

## Protection

- Only accepts certain commands: see `allowedCommands.js`. If the body contains a command not in the list, the server will respond with a 400 status code. It also ignores differently formatted requests.

- Rate limiting: the server will respond with a 429 status code if the same IP address sends invalid requests too frequently.

- Accepts UUIDs to help better understand how users interact with the CLI.