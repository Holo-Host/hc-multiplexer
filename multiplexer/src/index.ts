import express, { Application, Request, Response } from "express";
import {
  AdminWebsocket,
  decodeHashFromBase64,
  encodeHashToBase64,
  getSigningCredentials
} from "@holochain/client";
// import { HoloHash } from '@whi/holo-hash';

import cookieParser from "cookie-parser"
const app: Application = express();

const PORT = process.env.PORT || 3000;
const ADMIN_PORT = process.env.ADMIN_PORT || 3001;

const HAPP_PATH = process.env.HAPP_PATH || "/home/eric/code/metacurrency/holochain/emergence/workdir/emergence.happ"

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

const makeKey = async (adminWebsocket: AdminWebsocket, seedStr: string) => {
  const pubKey = await adminWebsocket.generateAgentPubKey();
  return encodeHashToBase64(pubKey)
};

app.post("/regkey/:key", async (req: Request, res: Response) => {
  const url = `ws://127.0.0.1:${ADMIN_PORT}`
  const adminWebsocket = await AdminWebsocket.connect(url);
  
  const apps = await adminWebsocket.listApps({});
  const installed_app_id = `emergence-${req.params.key}`
  if (!apps.find((info)=> info.installed_app_id == installed_app_id)) {
    const agentPubKeyB64 = await makeKey(adminWebsocket,`${req.body.password}-${req.params.key}`);
    console.log("making: ", agentPubKeyB64)
    const agent_key = decodeHashFromBase64(agentPubKeyB64)
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
      res.send(`error ${JSON.stringify(e)}`);
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
  console.log("DSF", cellIds.map(i=>encodeHashToBase64(i[1])))
  res.cookie('name', 'express'); //Sets name = express
  // const x:any = new HoloHash("WxWLBLEXLOAtLrfo2AZXWCg9ARt9mMkILJfti4rSjaw")
  // console.log("X",encodeHashToBase64(x))
  res.send("Go get your reg packet and scan the QR code!");
});

app.listen(PORT, (): void => {
  console.log("SERVER IS UP ON PORT:", PORT);
});
