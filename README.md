# hc-multiplexer

A small webserver that manages creation of agent instances and UI password access for zome calls to those instances.

## Description

We need a temporary solution for browsers on a local-area-network to access Holochain instances.  Thus we create a proxy web service that "multiplexes" connections to a conductor and makes them available over the web, as simplified hosting solution.  The service requests a registration key and password from the user. It checks to see if an instance of the happ with that registration key has been created.  

If the instance doesn't exist it:
1.  uses the password and key as a seed to create an agent keypair in lair
2.  creates an instance of the happ using that keypair as the agent and the registration key as the installed_app_id
3.  derives signing credentials from the key and password
4.  creates a full permisions CapGrant with those credentials for the UI to use credentials to sign zome calls
5.  returns those credentials to the UI in the form of a cookie

If the instance does exist it does steps 3 & 5 above.

For this system to work, it also requires a reverse proxy setup to make public this web-server AND route websocket connections to the locally running conductor.  A sample reverse proxy config for caddy can be found [here](Caddyfile)

## Dev testing:

### Setup
1. Install lair-keystore-cli at branch `lair-keystore-cli` using:
```
git clone https://github.com/holochain/lair.git
cd lair
git checkout lair-keystore-cli
cd crates/lair_keystore_cli
cargo install --path .
which lair-keystore-cli
```
Add the binary path shown to LAIR_CLI_PATH in step 3

2. Install emergence: and `npm i` `npm run package`

3. Create a `multiplexer/.env` file with:
```
HAPP_UI_PATH="/path/to/emergence/ui/dist"
HAPP_PATH="/path/to/emergence/workdir/emergence.happ"
WEBHAPP_PATH="/path/to/emergence/workdir/emergence.webhapp"
CONDUCTOR_CONFIG_PATH="" #default is get this from the .hc file created by `hc s g`
LAIR_CLI_PATH="/path/to/bin/lair-keystore-cli"
INSTANCE_COUNT="1"
APP_PATH_FOR_CLIENT="appWebsocket"
NETWORK_SEED="some-unique-value"
```

4. install caddy  with:
```
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```
 copy Caddyfile from hc-multiplexer to `/etc/caddy` 

copy the pem files into /var/lib/secrets/infra.holochain.org

5. chown the pem files to `caddy:caddy`

6. restart caddy with `systemctl restart caddy`

7. add a host:` mydweb1.infra.holochain.org  127.0.0.1` to your `/etc/hosts/` file 

8. Run:
```
cd multiplexer
npm i
npm run dev
```
Then you should be able to go to `mydweb1.infra.holochain.org` locally


## Live Setup

1. make sure the following binarys are available on the system:
   - holochain
   - lair
   - caddy
2. put the app's `.happ` `.webhapp` and `ui/dist` someplace on the system.
3. configure caddy with [this config file](Caddyfile) in `/etc/caddy` editing the domain name to match what you have set up.
4. make sure `pem` files for your cert are in the right place as indicated by the caddy file.
5. Create a `.env` file similar to above
6. ensure that your server spins up the node server `npm run start`


## License

Copyright (C) 2023, Holochain Foundation, All rights reserved.

This software may not be used without a commercial license from the Holochain Foundation.
