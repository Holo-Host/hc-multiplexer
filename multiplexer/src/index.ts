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
const app: Application = express();

const PORT = process.env.PORT || 3000;
const ADMIN_PORT = process.env.ADMIN_PORT || 3001;
const HAPP_UI_PATH = process.env.HAPP_UI_PATH || "./"
const HAPP_PATH = process.env.HAPP_PATH|| ""
const LAIR_CLI_PATH = process.env.LAIR_CLI_PATH|| ""

const INSTANCE_COUNT = parseInt(process.env.INSTANCE_COUNT ? process.env.INSTANCE_COUNT : "1")
const MY_INSTANCE_NUM = parseInt(process.env.MY_INSTANCE_NUM ? process.env.MY_INSTANCE_NUM : "1")
const APP_PORT_FOR_CLIENT = process.env.APP_PORT_FOR_CLIENT || '3030'

const instanceForRegKey = (regkey:string):number => {
  return (Buffer.from(regkey)[0] % INSTANCE_COUNT) +1
}

const myExec = (cmd:string) => {
  console.log("Executing", cmd)
  let output = execSync(cmd).toString()
  output = output.substring(0, output.length - 1);
  return output
}
const getLairSocket = () => {
  let hc = myExec("cat .hc")
  const cmd = `sed -n 's/.*connection_url: \\(.*\\)/\\1/p' ${hc}/conductor-config.yaml`
  let lairSocket = myExec(cmd)
  return lairSocket
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

  const url = `ws://127.0.0.1:${ADMIN_PORT}`
  const adminWebsocket = await AdminWebsocket.connect(url);
  
  const apps = await adminWebsocket.listApps({});
  const installed_app_id = installedAppId(regkey)
  const appInfo = apps.find((info)=> info.installed_app_id == installed_app_id)

  if (!appInfo) {
    const agent_key = await makeKey(adminWebsocket,`${req.body.password}-${regkey}`);
    if (agent_key) {
      try {
        const appInfo = await adminWebsocket.installApp({
          agent_key,
          path: HAPP_PATH,
          installed_app_id,
          membrane_proofs: {},
        });
        await adminWebsocket.enableApp({ installed_app_id });

        console.log("installing", req.params.key, appInfo);
        // @ts-ignore
        const { cell_id } = appInfo.cell_info["emergence"][0]["provisioned"]

        setCredsForPass(true, regkey, res, adminWebsocket, cell_id, installed_app_id, req.body.password)

      } catch (e) {
        throw(e)
//        res.send(`error installing app ${JSON.stringify(e)}`);
      }
    } else {
      doSend(res,`<h2>error creating agent_key</h2>`);
    }
  } else {
    //@ts-ignore
    const { cell_id } = appInfo.cell_info["emergence"][0]["provisioned"]
    setCredsForPass(false, regkey, res, adminWebsocket, cell_id, installed_app_id, req.body.password)
  }
});

const handleReg = async (regkey:string, req: Request, res:Response) => {
  if (redirecting(regkey, req, res)) {
    return
  }

  const url = `ws://127.0.0.1:${ADMIN_PORT}`
  const adminWebsocket = await AdminWebsocket.connect(url);
  const apps = await adminWebsocket.listApps({});
  const installed_app_id = installedAppId(regkey)
  const appInfo = apps.find((info)=> info.installed_app_id == installed_app_id)
  if (appInfo) {
    doSend(res,`
Please enter a password to login as ${regkey}
<form action="/regkey/${regkey}" method="post">
  Password <input type="password" name="password"></input>
  <input type="submit" name="submit"></input>
</form>
`);
  }
  else {
    doSend(res,`
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
  console.log("FISH", pass1, pass2)
}
const submitButton = document.getElementById("submit")
submitButton.addEventListener("click",checkpass)
</script>
`);

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

app.get("/", [async (req: Request, res: Response, next: NextFunction) => {
  
  const url = `ws://127.0.0.1:${ADMIN_PORT}`
  const adminWebsocket = await AdminWebsocket.connect(url);
  const cellIds = await adminWebsocket.listCellIds()

  if (req.cookies["creds"]) {
    const creds = JSON.parse(req.cookies["creds"])
    if (redirecting(creds.regkey, req, res)) {
      return
    }

    res.redirect("/index.html")
  } else {
    doSend(res,`

  <h2>Welcome to Emergence, a Holochain App for Dweb</h2>
  <div>To create an agent please find Emergence Registration Key in your conference registration packet
  and either scan the QR code, or type it in below:
  </div>
    <form action="/regkey/" method="post">
    Reg Key <input type="input" name="key"></input>
    <input type="submit" name="submit"></input>
  </form>

    `);
  }
}]);

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
        font-size: 16px;
        line-height: 1.5;
        color: #333;
        padding: 0px;
        padding-bottom: 76px; /* Adjust this value based on the height of your bottom navigation */
        height: 100%; overflow: hidden; /* In general, it's a good idea to have the body take up the full viewport height and have a fixed layout with no scrollbar. Then, you can have a scrollable inner container like .pane-content to handle the overflow of the content. This approach helps keep the page structure clean and allows you to control the scrolling behavior more effectively. */
      }
      </style>
    </head>
    <body>
      <h1>Emergence: Mobile Access</h2>
      ${body}
    </body>
  </html>
  `
  res.send(page)
}
 
app.use('/', express.static(HAPP_UI_PATH)); 

app.get("/reset", (req: Request, res: Response): void => {
  res.clearCookie("creds")
  res.redirect('/');
});
app.listen(PORT, (): void => {
  console.log("SERVER IS UP ON PORT:", PORT); 
});
