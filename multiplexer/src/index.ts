#!/usr/bin/env node

import express, { Application, Request, Response, NextFunction } from "express";
import {
  AdminWebsocket,
  AgentPubKey, GrantedFunctionsType, CellId, GrantedFunctions
} from "@holochain/client";
// import { HoloHash } from '@whi/holo-hash';
import blake2b  from 'blake2b'
//import * as ed25519 from "@noble/ed25519";
import nacl from "tweetnacl";

import {execSync} from "child_process"
import 'dotenv/config'
// @ts-ignore
globalThis.crypto = await import("node:crypto")

import cookieParser from "cookie-parser"
import * as fs from 'fs';

const app: Application = express();


// Here we assign our handler to the corresponding global, window property
process.on('unhandledRejection', error => {
  // Prints "unhandledRejection woops!"
  console.log('unhandledRejection:', error);
});
// production error handler

const myExec = (cmd:string) => {
  console.log("Executing", cmd)
  let output = execSync(cmd).toString()
  output = output.substring(0, output.length - 1);
  return output
}

const configPathFromDotHC = () => {
  let data = fs.readFileSync('.hc', 'utf8');
  data = data.substring(0, data.length - 1);

  return `${data}/conductor-config.yaml`
}

const CONDUCTOR_CONFIG_PATH = process.env.CONDUCTOR_CONFIG_PATH || configPathFromDotHC()
const CONDUCTOR_CONFIG = fs.readFileSync(CONDUCTOR_CONFIG_PATH, 'utf8');
const adminPortFromConfig = () => {
  const result = CONDUCTOR_CONFIG.match(/driver:\W+type: websocket\W+port: ([0-9]+)/m)
  if (!result) throw("Unable to find admin port in config")
  return result[1]
}
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const HC_ADMIN_PORT = process.env.HC_ADMIN_PORT || adminPortFromConfig();
const HAPP_UI_PATH = process.env.HAPP_UI_PATH || "./"
const HAPP_PATH = process.env.HAPP_PATH|| ""
const WEBHAPP_PATH = process.env.WEBHAPP_PATH|| ""
const LAIR_CLI_PATH = process.env.LAIR_CLI_PATH|| ""
const NETWORK_SEED = process.env.NETWORK_SEED|| ""

const INSTANCE_COUNT = parseInt(process.env.INSTANCE_COUNT ? process.env.INSTANCE_COUNT : "1")
const MY_INSTANCE_NUM = parseInt(process.env.MY_INSTANCE_NUM ? process.env.MY_INSTANCE_NUM : "1")
const APP_PORT_FOR_CLIENT = process.env.APP_PORT_FOR_CLIENT || '3030'

const instanceForRegKey = (regkey:string):number => {
  return (Buffer.from(regkey)[0] % INSTANCE_COUNT) +1
}

const getLairSocket = () => {
  // prefer getting the url from lair-keystore directly
  if (process.env.LAIR_PATH && process.env.LAIR_WORKING_DIRECTORY) {
    const cmd = `${process.env.LAIR_PATH} --lair-root ${process.env.LAIR_WORKING_DIRECTORY} url`

    try {
      const output = myExec(cmd)
      return output
    } catch (e) {
      console.log("Error when while attempting to read lair-keystore url: ", e)
    }
  }

  // fallback to parsing the conductor config
  const result = CONDUCTOR_CONFIG.match(/.*connection_url: (.*)/)
  if (!result) throw("Unable to find connectuion URL")
  return result[1]
}



const uint8ToBase64 = (arr:Uint8Array) => Buffer.from(arr).toString('base64');
const base64ToUint8 = (b64:string)=> Uint8Array.from(Buffer.from(b64, 'base64'));

const deriveSigningKeys = async (seed: string): Promise<
  [nacl.SignKeyPair, AgentPubKey]
> => {
  //const interim = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
//  const privateKey = await blake2b(interim.length).update(Buffer.from(seed)).digest('binary')
//  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
//  const keyPair = { privateKey, publicKey };

  const interim = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  const seedBytes = await blake2b(interim.length).update(Buffer.from(seed)).digest('binary')

  const keyPair = nacl.sign.keyPair.fromSeed(seedBytes)

  const signingKey = new Uint8Array(
    [132, 32, 36].concat(...keyPair.publicKey).concat(...[0, 0, 0, 0])
  );
  return [keyPair, signingKey];
};

const credsToJson = (creds:any, installed_app_id: string, regkey: string) => {
  return JSON.stringify(
    {installed_app_id,
    regkey,
    appPort: APP_PORT_FOR_CLIENT,
    creds: {
        capSecret:uint8ToBase64(creds.capSecret),
        keyPair:{
          publicKey: uint8ToBase64(creds.keyPair.publicKey),
          secretKey: uint8ToBase64(creds.keyPair.secretKey),
        },
        signingKey: uint8ToBase64(creds.signingKey)
      }
    })
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


const hash32ToAgentPubKey = (pubKey32: Buffer) : AgentPubKey => {
  const interim = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  const hash = blake2b(interim.length).update(pubKey32).digest('binary')
  const dhtLoc = Buffer.from([hash[0], hash[1], hash[2], hash[3]])
  for (let i of [4, 8, 12]) {
    dhtLoc[0] ^= hash[i];
    dhtLoc[1] ^= hash[i + 1];
    dhtLoc[2] ^= hash[i + 2];
    dhtLoc[3] ^= hash[i + 3];
  }
  const pubKey = Buffer.concat([Buffer.from([132, 32, 36]),pubKey32,dhtLoc])
  return pubKey
}

const makeKey = async (adminWebsocket: AdminWebsocket, seedStr: string) => {
  
  const cmd = `echo "pass" | ${LAIR_CLI_PATH} import-seed-string "${getLairSocket()}" "${seedStr}"`

  try {
    const output = myExec(cmd)
    console.log("RAW", output)
    let b64 = ""
    if (output.startsWith("BinDataSized")) { ///CRAZY
      let last = output.split('(')[1]
      b64 = last.substring(0, last.length - 1);
    } else {
      b64 = output
    }
    const pubKey = hash32ToAgentPubKey(Buffer.from(b64, 'base64'))
    return pubKey
  } catch (e) {
    console.log("Error when while attempting to add agent: ", e)
    return undefined
  }
};
const grantUIPassword = async (
  adminWebSocket: AdminWebsocket,
  cellId: CellId,
  capSecret: Uint8Array,
  functions: GrantedFunctions,
  signingKey: AgentPubKey
): Promise<void> => {
  await adminWebSocket.grantZomeCallCapability({
    cell_id: cellId,
    cap_grant: {
      tag: "zome-call-signing-key",
      functions,
      access: {
        Assigned: {
          secret: capSecret,
          assignees: [signingKey],
        },
      },
    },
  });
};


const setCredsForPass = async (doGrant: boolean, regkey: string, res: Response, adminWebsocket: AdminWebsocket, cell_id: CellId, installed_app_id: string, password: string) => {
  const [keyPair, signingKey] = await deriveSigningKeys(`${regkey}-${password}`)
  const interim = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  const regKeyHash = await blake2b(interim.length).update(Buffer.from(regkey)).digest('binary')
  const capSecret = Buffer.concat([regKeyHash,regKeyHash]);
  if (doGrant) {
    await grantUIPassword(adminWebsocket,cell_id, capSecret, { [GrantedFunctionsType.All]: null }, signingKey)
  }

  const creds = {
    capSecret,
    keyPair,
    signingKey
  }

  const credsJSON = credsToJson(creds, installed_app_id, regkey)
  res.cookie('creds', credsJSON); 
  res.redirect('/');

}

const installedAppId = (regKey: string) => {
  return `emergence-${regKey}`
}

app.post("/regkey/:key", async (req: Request, res: Response) => {
  const regkey = req.params.key

  if (redirecting(regkey, req, res)) {
    return
  }

  try {

    const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`
    const adminWebsocket = await AdminWebsocket.connect(url);
    
    const apps = await adminWebsocket.listApps({});
    const installed_app_id = installedAppId(regkey)
    const appInfo = apps.find((info)=> info.installed_app_id == installed_app_id)

    if (!appInfo) {
      const agent_key = await makeKey(adminWebsocket,`${req.body.password}-${regkey}`);
      if (agent_key) {
        const appInfo = await adminWebsocket.installApp({
          agent_key,
          path: HAPP_PATH,
          installed_app_id,
          membrane_proofs: {},
          network_seed: NETWORK_SEED,
        });
        await adminWebsocket.enableApp({ installed_app_id });

        console.log("installing", req.params.key, appInfo);
        // @ts-ignore
        const { cell_id } = appInfo.cell_info["emergence"][0]["provisioned"]

        await setCredsForPass(true, regkey, res, adminWebsocket, cell_id, installed_app_id, req.body.password)
      } else {
        doSend(res,`<h2>error creating agent_key</h2>`);
      }
    } else {
      //@ts-ignore
      const { cell_id } = appInfo.cell_info["emergence"][0]["provisioned"]
      await setCredsForPass(false, regkey, res, adminWebsocket, cell_id, installed_app_id, req.body.password)
    }
  } catch(e) {
    doError(res, e)
  }
});

const handleReg = async (regkey:string, req: Request, res:Response) => {
  if (redirecting(regkey, req, res)) {
    return
  }

  try {
    const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`
    const adminWebsocket = await AdminWebsocket.connect(url);
    const apps = await adminWebsocket.listApps({});
    const installed_app_id = installedAppId(regkey)
    const appInfo = apps.find((info)=> info.installed_app_id == installed_app_id)
    let body
    if (appInfo) {
      body = `
  Please enter a password to login as ${regkey}
  <form action="/regkey/${regkey}" method="post">
    Password <input type="password" name="password"></input>
    <input type="submit" name="submit"></input>
  </form>
  `;
    }
    else {
      body = `
<div>Please enter a password to create an agent for ${regkey}</div>
<div><b>Make sure your write down this password as it cannot be changed!</b></div>
<form action="/regkey/${regkey}" method="post">
<div style="display:flex; flex-direction:column;">
<div>Password: <input id="pass1" type="password" name="password"></input></div>
<div>Confirm: <input id="pass2" type="password" name="password2"></input></div>
<div><input id="submit" type="submit" name="submit""></input></div>
</div>
</form>
<script>
function checkpass(e) {
  const pass1 = document.getElementById("pass1").value
  const pass2 = document.getElementById("pass2").value
  if (pass1 != pass2) {
    alert("passwords don't match!")
    e.preventDefault()
  }
}
const submitButton = document.getElementById("submit")
submitButton.addEventListener("click",checkpass)
</script>
  `;
    }
    doSend(res,body)
  } catch(e) {
    doError(res, e)
  }
 
}

app.post("/regkey", async (req: Request, res: Response) => {
  await handleReg(req.body.key, req, res)
});

app.get("/regkey/:key", async (req: Request, res: Response) => {
  await handleReg(req.params.key, req, res)
});

// const happ = function (_req: Request, res: Response) {
//   res.sendFile(path.join(__dirname, '/index.html'));
// }

const redirecting = (regkey: string, req: Request, res: Response): boolean => {
  const origin = req.headers.origin
  if (origin) {
    const hostForRegkey = instanceForRegKey(regkey)
    const found = origin.match(/(.*)([0-9]+)(\..*\.*)/)

    if (found && parseInt(found[2]) != hostForRegkey) {
      const target = `${req.headers['x-forwarded-proto']}://${found[1]}${hostForRegkey}${found[3]}`
      console.log("REDIRECTING TO ", target)
      res.redirect(target)
      return true
    } 
  }
  return false

}
app.get('/emergence.webhapp', async (req: Request, res: Response) => {
  res.sendFile(WEBHAPP_PATH)
}); 
app.get("/install", async (req: Request, res: Response) => {
  const network_seed = NETWORK_SEED ? `
  <li>
  IMPORTANT: add "${NETWORK_SEED}" as the network seed!
  </li>  
  ` : ``
  doSend(res,`
<h3>Launcher Install Instructions:</h3>
<ol style="text-align: left">
<li>
Download the the <a href="https://drive.switch.ch/index.php/s/eRCdJxAuSWW2YPp">Launcher for your platfrom</a>
</li>
<li>
Download the <a href="emergence.webhapp">Emergence webhapp file</a>
</li>
<li>
Open the launcher and click on "App Store," then "Select app from Filesystem" and choose the file you downloaded from step 2.
</li>
${network_seed}
<li>
Enjoy!
</li>
</ol>
`)
});

app.get("/", [async (req: Request, res: Response, next: NextFunction) => {
  try {
    const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`
    const adminWebsocket = await AdminWebsocket.connect(url);
    const cellIds = await adminWebsocket.listCellIds()
  } catch(e) {
    doError(res, e)
    return
  }
  if (req.cookies["creds"]) {
    const creds = JSON.parse(req.cookies["creds"])
    if (redirecting(creds.regkey, req, res)) {
      return
    }

    res.redirect("/index.html")
  } else {
    doSend(res,`
  <h3>Welcome to Emergence, a Holochain App for Dweb</h3>
  <div>To create an agent or log-in, please use the Emergence Registration Key from your conference registration packet
  and either scan the QR code, or enter it here:
  </div>
    <form action="/regkey/" method="post">
    Reg Key <input type="input" name="key"></input>
    <input type="submit" name="submit"></input>
  </form>
  <p style="margin-top:20px; color:gray; font-size:14px">
    If you want to install the holochain-native emergence hApp on your computer instead, please follow <a href="/install"> these instructions.</a>
  </p>
    `);
  }
}]);

const doError = (res:Response, err: any) => {
  doSend(res,`
  <div style="border: solid 1px; border-radius:10px;padding:0 20px 20px 20px;min-width:300px;">
  <h4>Error!</h4>
  ${err.message ?  err.message : JSON.stringify(err)}
  </div>
  `)
}

const doSend = (res:Response, body:string) => {
  const page = `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
  
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Emergence Agent Setup</title>
      <style>
      html, body {
        font-family: "Roboto", sans-serif;
        font-size: 18px;
        line-height: 1.5;
        color: #333;
        padding: 0px;
        padding-bottom: 76px; /* Adjust this value based on the height of your bottom navigation */
        height: 100%; overflow: hidden; /* In general, it's a good idea to have the body take up the full viewport height and have a fixed layout with no scrollbar. Then, you can have a scrollable inner container like .pane-content to handle the overflow of the content. This approach helps keep the page structure clean and allows you to control the scrolling behavior more effectively. */
      }
      .app-info {
        display:flex; justify-content:center; align-items:center; flex-direction: column;
        max-width: 500px;
        margin:0 auto;
        text-align: center;
      }
      </style>
    </head>
    <body>
      <div class="app-info">
      <a href="/"><img width="75" src="/images/emergence-vertical.svg" /></a>
      <h2> Web Access</h2>
      ${body}
      </div>
    </body>
  </html>
  `
  res.send(page)
}
app.get("/fail" ,async (req: Request, res: Response) => {
  try {
    throw("test error")
  } catch(e) {
    doError(res,e)
  }
});

app.use('/', express.static(HAPP_UI_PATH)); 

app.get("/reset", (req: Request, res: Response): void => {
  res.clearCookie("creds")
  res.redirect('/');
});
app.listen(PORT, "0.0.0.0", (): void => {
  console.log("SERVER IS UP ON PORT:", PORT); 
});

