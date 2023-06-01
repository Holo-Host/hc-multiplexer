# hc-multiplexer

A small webserver that manages creation of agent instances and UI password access for zome calls to those instances.

## Description

We need a temporary solution for mobile devices to access Holochain.  Thus we create a proxy web service that "multiplexes" connections to a conductor and makes them available over the web, as simplified hosting solution.  The service requests a registration key and password from the user. It checks to see if an instance of the happ with that registration key has been created.  

If the instance doesn't exist it:
1.  uses the password and key as a seed to create an agent keypair in lair
2.  creates an instance of the happ using that keypair as the agent and the registration key as the installed_app_id
3.  derives signing credentials from the key and password
4.  creates a full permisions CapGrant with those credentials for the UI to use credentials to sign zome calls
5.  returns those credentials to the UI in the form of a cookie

If the instance does exist it does steps 3 & 5 above.

For this system to work, it also requires a reverse proxy setup to make public this web-server AND route websocket connections to the locally running conductor.  A sample reverse proxy config for nginx can be found [here](00-reverse-proxy.conf)

## Dev testing:

### Setup

1. Install lair-keystore-cli at branch `lair-keystore-cli` using:
```
cd crate/lair_keystore_cli
cargo install --path .
which lair-keystore-cli
```
Add the binary path shown in step 2

2. Compile and package your happ and UI files.

3. Create a `multiplexer/.env` file with:
```
HAPP_UI_PATH="/path/to/your-app/ui/dist"
HAPP_PATH="/path/to/your-app.happ"
LAIR_CLI_PATH="/path/to/bin/lair-keystore-cli"
INSTANCES="ws://localhost:3000"
APP_WS_URL="ws://localhost:3030"
```

3. Run:
```
cd multiplexer
npm i
npm run dev
```

To test using the reverse proxy:

1. create a domain name that points to your local IP address (yes this is werid!)
2. install ngix and copy [this config file](00-reverse-proxy.conf) to `/etc/nginx/conf.d` editing the domain name to match what you have set up.
3. Edit the `INSTANCES` and `APP_WS_URL` items of the `.env` file to match your domain name and ports.

On a local network this should work without installing any SSL certs.


## Live Setup

1. make sure the following binarys are available on the system:
   - holochain
   - lair
   - nginx
2. put the app's `.happ` file and ui someplace on the system.
3. configure nignx with [this config file](00-reverse-proxy.conf) in `/etc/nginx/conf.d` editing the domain name to match what you have set up.
4. Create a `.env` file as above but pointing to the live resources
5. ensure that holochain's config accepts app port websocket requests that match your UI (3030 for emergence) and that the nginx reverse proxy support is proxying from that port.
6. ensure that your server spins up the node server `npm run start`
