# hc-multiplexer

A small webserver that manages creation of agent instances and UI password access for zome calls to those isntances.

## Dev testing:

### Setup

1. Install lair-keystore-cli at branch `lair-keystore-cli` using:
```
cd crate/lair_keystore_cli
cargo install --path .
which lair-keystore-cli
```
Add the binary path shown in step 2

2. Create a `multiplexer/.env` file with:
```
HAPP_UI_PATH="/path/to/happ/ui/dist"
HAPP_PATH="/path/to/your-app.happ"
LAIR_CLI_PATH="/path/to/bin/lair-keystore-cli"
INSTANCES="ws://localhost:3000"
```

3. Run:
```
cd multiplexer
npm i
npm run dev
```

