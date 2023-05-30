import express, { Application, Request, Response } from "express";
import {
  AdminWebsocket,
  encodeHashToBase64,
  getSigningCredentials,
  AgentPubKey,
} from "@holochain/client";
// import { HoloHash } from '@whi/holo-hash';
import blake2b  from 'blake2b'

import {execSync} from "child_process"


import cookieParser from "cookie-parser"
const app: Application = express();

const PORT = process.env.PORT || 3000;
const ADMIN_PORT = process.env.ADMIN_PORT || 3001;

const HAPP_PATH = process.env.HAPP_PATH || "/home/eric/code/metacurrency/holochain/emergence/workdir/emergence.happ"
const LAIR_CLI_PATH = process.env.LAIR_CLI_PATH ||"/home/eric/code/metacurrency/holochain/emergence/.cargo/bin/lair-keystore-cli"

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


const credsToJson = (creds:any) => JSON.stringify({
  capSecret:uint8ToBase64(creds.capSecret),
  keyPair:{
    publicKey: uint8ToBase64(creds.keyPair.publicKey),
    secretKey: uint8ToBase64(creds.keyPair.secretKey),
  },
  signingKey: uint8ToBase64(creds.signingKey)
});
const jsonToCreds = (json:string)=> {
  const creds = JSON.parse(json)
  return {
  capSecret:base64ToUint8(creds.capSecret),
  keyPair:{
    publicKey: base64ToUint8(creds.keyPair.publicKey),
    secretKey: base64ToUint8(creds.keyPair.secretKey),
  },
  signingKey: base64ToUint8(creds.signingKey)
}};

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

app.post("/regkey/:key", async (req: Request, res: Response) => {
  const url = `ws://127.0.0.1:${ADMIN_PORT}`
  const adminWebsocket = await AdminWebsocket.connect(url);
  
  const apps = await adminWebsocket.listApps({});
  const installed_app_id = `emergence-${req.params.key}`
  if (!apps.find((info)=> info.installed_app_id == installed_app_id)) {
    const agent_key = await makeKey(adminWebsocket,`${req.body.password}-${req.params.key}`);
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
        await adminWebsocket.authorizeSigningCredentials(cell_id)
        const creds = getSigningCredentials(cell_id)
        const credsJSON = credsToJson(creds)
        res.send(`INSTALLED ${credsJSON}`);


      } catch (e) {
        res.send(`error installing app ${JSON.stringify(e)}`);
      }
    } else {
      res.send(`error creating agent_key`);
    }
  } else {
    res.send(`already installed`);
  }
});

app.get("/regkey/:key", (req: Request, res: Response): void => {
  res.send(`Your key ${req.params.key}
  <form action="/regkey/${req.params.key}" method="post">
    Password <input type="password" name="password"></input>
    <input type="submit" name="submit"></input>
  </form>
  `);
});


app.get("/", async (_req: Request, res: Response) => {
  const url = `ws://127.0.0.1:${ADMIN_PORT}`
  const adminWebsocket = await AdminWebsocket.connect(url);
  const cellIds = await adminWebsocket.listCellIds()
  res.cookie('name', 'express'); //Sets name = express

  const agent = await makeKey(adminWebsocket,"fishy")
  console.log("agentB64", agent ? encodeHashToBase64(agent) : "couldn't make key")

  res.send("Go get your reg packet and scan the QR code!");
});
 console.log("BEFORE")

app.listen(PORT, (): void => {
  console.log("SERVER IS UP ON PORT:", PORT);
});
