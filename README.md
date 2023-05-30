# hc-multiplexer


## Dev testing:

### Setup

Create a `multiplexer/.env` file with:
```
HAPP_UI_PATH="/path/to/happ/ui/dist"
HAPP_PATH="/path/to/your-app.happ"
LAIR_CLI_PATH="/path/to/bin/lair-keystore-cli"
INSTANCES="localhost:3000"
```

Run:
```
cd multiplexer
npm i
npm run dev
```

