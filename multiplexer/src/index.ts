#!/usr/bin/env node

import msgpack from "msgpack-lite";
import { WebSocket, WebSocketServer } from "ws";
import express, { Application, Request, Response, NextFunction } from "express";
import {
  AdminWebsocket,
  AgentPubKey,
  GrantedFunctionsType,
  CellId,
  GrantedFunctions,
  encodeHashToBase64,
  SigningCredentials,
  KeyPair,
} from "@holochain/client";
// import { HoloHash } from '@whi/holo-hash';
import blake2b from "blake2b";
import { ed25519 } from "@noble/curves/ed25519";

import { execSync } from "child_process";
import "dotenv/config";
// @ts-ignore
globalThis.crypto = await import("node:crypto");

import cookieParser from "cookie-parser";
import * as fs from "fs";

const app: Application = express();

// Here we assign our handler to the corresponding global, window property
process.on("unhandledRejection", (error) => {
  // Prints "unhandledRejection woops!"
  console.log("unhandledRejection:", error);
});
// production error handler

const myExec = (cmd: string) => {
  console.log("Executing", cmd);
  let output = execSync(cmd).toString();
  output = output.substring(0, output.length - 1);
  return output;
};

const dotHCpath = (conductor: number) => {
  let data = fs.readFileSync(".hc", "utf8");
  const dirs = data.substring(0, data.length - 1).split(/\n/);
  return dirs[conductor];
};

const configPathFromDotHC = (conductor: number) => {
  const data = dotHCpath(conductor);
  return `${data}/conductor-config.yaml`;
};

const lairWorkdirPathFromDotHC = (conductor: number) => {
  const data = dotHCpath(conductor);
  return `${data}/keystore`;
};

const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const HAPP_UI_PATH = process.env.HAPP_UI_PATH || "./";
const HAPP_PATH = process.env.HAPP_PATH || "";
const WEBHAPP_PATH = process.env.WEBHAPP_PATH || "";
const LAIR_CLI_PATH = process.env.LAIR_CLI_PATH || "";
const NETWORK_SEED = process.env.NETWORK_SEED || "";
const MAC_PATH = process.env.MAC_PATH || "";
const LINUX_PATH = process.env.LINUX_PATH || "";
const WINDOWS_PATH = process.env.WINDOWS_PATH || "";

const INSTANCE_COUNT = parseInt(
  process.env.INSTANCE_COUNT ? process.env.INSTANCE_COUNT : "1"
);
const CONDUCTOR_COUNT = parseInt(
  process.env.CONDUCTOR_COUNT ? process.env.CONDUCTOR_COUNT : "1"
);
const APP_PATH_FOR_CLIENT = process.env.APP_PATH_FOR_CLIENT || "appWebsocket";
const REAL_APP_PORT_FOR_INTERFACE: number = parseInt(
  process.env.REAL_APP_PORT_FOR_INTERFACE || "30030"
);
const APP_PORT_FOR_INTERFACE: number = parseInt(
  process.env.APP_PORT_FOR_INTERFACE || "3030"
);

const getHcAdminPortsFromEnv = (): Array<string>|undefined => {
  var env = process.env.HC_ADMIN_PORTS;
  if (env) {
    return env.split(",");
  } else {
    return undefined;
  }
};

const getHcAdminPortsFromDotHc = (): Array<string> => {
  var array: Array<string> = [];
  for (let i = 0; i < CONDUCTOR_COUNT; i += 1) {
    const configPath = configPathFromDotHC(i);
    const config = fs.readFileSync(configPath, "utf8");
    const result = config.match(/driver:\W+type: websocket\W+port: ([0-9]+)/m);
    if (!result) throw "Unable to find admin port in config";
    console.log(`Conductor ${i} on admin port ${result[1]}`);
    array[i] = result[1];
  }

  return array;
};

const HC_ADMIN_PORTS: Array<number> = (
  getHcAdminPortsFromEnv() || getHcAdminPortsFromDotHc()
).map((s) => parseInt(s));

const instanceForRegKey = (regkey: string): number => {
  return (Buffer.from(regkey)[0] % INSTANCE_COUNT) + 1;
};

const conductorForRegKey = (regkey: string): number => {
  return Buffer.from(regkey)[0] % CONDUCTOR_COUNT;
};

const lairBin = process.env.LAIR_PATH;

const getLairRootFromEnv = (conductor: number): string => {
  try {
    var env = process.env.LAIR_WORKING_DIRECTORIES;
    if (env) {
      return env.split(",")[conductor];
    } else {
      return "";
    }
  } catch (e: any) {
    throw `error creating agent_key ${e.message}`;
  }
};

const getLairSocket = (conductor: number) => {
  const lairRoot =
    getLairRootFromEnv(conductor) || lairWorkdirPathFromDotHC(conductor);

  // prefer getting the url from lair-keystore directly
  if (lairBin && lairRoot) {
    const cmd = `${lairBin} --lair-root ${lairRoot} url`;

    try {
      const output = myExec(cmd);
      return output;
    } catch (e) {
      console.log("Error when while attempting to read lair-keystore url: ", e);
    }
  }
};

let globalAdminWebsockets: Array<AdminWebsocket> = [];

async function createAdminWebsocket(conductor: number) {
  const url = `ws://127.0.0.1:${HC_ADMIN_PORTS[conductor]}`;
  globalAdminWebsockets[conductor] = await AdminWebsocket.connect(new URL(url));
  console.log("connected to admin port at: ", url);
}

async function getAdminWebsocket(conductor: number): Promise<AdminWebsocket> {
  if (!globalAdminWebsockets[conductor]) {
    await createAdminWebsocket(conductor);
  }
  return globalAdminWebsockets[conductor];
}

const uint8ToBase64 = (arr: Uint8Array) => Buffer.from(arr).toString("base64");
const base64ToUint8 = (b64: string) =>
  Uint8Array.from(Buffer.from(b64, "base64"));

const deriveSigningKeys = async (
  seed: string
): Promise<[KeyPair, AgentPubKey]> => {
  //const interim = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  //  const privateKey = await blake2b(interim.length).update(Buffer.from(seed)).digest('binary')
  //  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  //  const keyPair = { privateKey, publicKey };

  const interim = Buffer.from([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  const privateKey = blake2b(interim.length)
    .update(Buffer.from(seed))
    .digest("binary");

  const publicKey = ed25519.getPublicKey(privateKey);

  const signingKey = new Uint8Array(
    [132, 32, 36].concat(...publicKey).concat(...[0, 0, 0, 0])
  );
  return [{ privateKey, publicKey }, signingKey];
};

const credsToJson = (
  conductor: number,
  creds: SigningCredentials,
  installed_app_id: string,
  regkey: string
) => {
  return JSON.stringify({
    installed_app_id,
    regkey,
    appPath: `${APP_PATH_FOR_CLIENT}${conductor}`,
    creds: {
      capSecret: uint8ToBase64(creds.capSecret),
      keyPair: {
        publicKey: uint8ToBase64(creds.keyPair.publicKey),
        privateKey: uint8ToBase64(creds.keyPair.privateKey),
      },
      signingKey: uint8ToBase64(creds.signingKey),
    },
  });
};

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const hash32ToAgentPubKey = (pubKey32: Buffer): AgentPubKey => {
  const interim = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const hash = blake2b(interim.length).update(pubKey32).digest("binary");
  const dhtLoc = Buffer.from([hash[0], hash[1], hash[2], hash[3]]);
  for (let i of [4, 8, 12]) {
    dhtLoc[0] ^= hash[i];
    dhtLoc[1] ^= hash[i + 1];
    dhtLoc[2] ^= hash[i + 2];
    dhtLoc[3] ^= hash[i + 3];
  }
  const pubKey = Buffer.concat([Buffer.from([132, 32, 36]), pubKey32, dhtLoc]);
  return pubKey;
};

const makeKey = async (
  conductor: number,
  adminWebsocket: AdminWebsocket,
  seedStr: string
) => {
  const cmd = `echo "pass" | ${LAIR_CLI_PATH} import-seed-string "${getLairSocket(
    conductor
  )}" "${seedStr}"`;

  // try {
  const output = myExec(cmd);
  console.log("RAW", output);
  let b64 = "";
  if (output.startsWith("BinDataSized")) {
    ///CRAZY
    let last = output.split("(")[1];
    b64 = last.substring(0, last.length - 1);
  } else {
    b64 = output;
  }
  const pubKey = hash32ToAgentPubKey(Buffer.from(b64, "base64"));
  return pubKey;
  // } catch (e) {
  //   console.log("Error when while attempting to add agent: ", e)
  //   return undefined
  // }
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

const genCredsForPass = async (regkey: string, password: string) => {
  const [keyPair, signingKey] = await deriveSigningKeys(
    `${regkey}-${password}`
  );
  const interim = Buffer.from([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  const regKeyHash = await blake2b(interim.length)
    .update(Buffer.from(regkey))
    .digest("binary");
  const capSecret = Buffer.concat([regKeyHash, regKeyHash]);
  const creds = {
    capSecret,
    keyPair,
    signingKey,
  };
  return creds;
};

const setCredsForPass = async (
  conductor: number,
  regkey: string,
  password: string,
  installed_app_id: string,
  res: Response
) => {
  const creds = await genCredsForPass(regkey, password);

  const credsJSON = credsToJson(conductor, creds, installed_app_id, regkey);
  res.cookie("creds", credsJSON);
  res.redirect("/");
};

const installedAppId = (regKey: string) => {
  return `emergence-${regKey}`;
};

const installAgent = async (
  conductor: number,
  adminWebsocket: AdminWebsocket,
  regkey: string,
  password: string
) => {
  const installed_app_id = installedAppId(regkey);
  const agent_key = await makeKey(
    conductor,
    adminWebsocket,
    `${password}-${regkey}`
  );
  if (agent_key) {
    const appInfo = await adminWebsocket.installApp(
      {
        agent_key,
        path: HAPP_PATH,
        installed_app_id,
        membrane_proofs: {},
        network_seed: NETWORK_SEED,
      },
      30000
    );
    await adminWebsocket.enableApp({ installed_app_id });

    console.log(`installing on conductor ${conductor}:`, regkey, appInfo);
    // @ts-ignore
    const { cell_id } = appInfo.cell_info["emergence"][0]["provisioned"];

    const creds = await genCredsForPass(regkey, password);

    await grantUIPassword(
      adminWebsocket,
      cell_id,
      creds.capSecret,
      { [GrantedFunctionsType.All]: null },
      creds.signingKey
    );
  } else {
    throw `error creating agent_key`;
  }
};

app.post("/regkey/:key", async (req: Request, res: Response) => {
  const regkey = req.params.key;
  const conductor = redirecting(regkey, req, res);
  if (conductor < 0) {
    return;
  }

  try {
    const adminWebsocket = await getAdminWebsocket(conductor);

    const apps = await adminWebsocket.listApps({});
    const installed_app_id = installedAppId(regkey);
    const appInfo = apps.find(
      (info) => info.installed_app_id == installed_app_id
    );

    if (!appInfo) {
      await installAgent(conductor, adminWebsocket, regkey, req.body.password);
    }
    await setCredsForPass(
      conductor,
      regkey,
      req.body.password,
      installed_app_id,
      res
    );
    //adminWebsocket.client.close();
  } catch (e) {
    doError(res, e);
  }
});

const handleReg = async (regkey: string, req: Request, res: Response) => {
  const conductor = redirecting(regkey, req, res);
  if (conductor < 0) {
    return;
  }
  try {
    const adminWebsocket = await getAdminWebsocket(conductor);
    const apps = await adminWebsocket.listApps({});
    const installed_app_id = installedAppId(regkey);
    const appInfo = apps.find(
      (info) => info.installed_app_id == installed_app_id
    );
    let body;
    if (appInfo) {
      body = `
<div class="card password-set"">
  Please enter a password to login as ${regkey}
  <form action="/regkey/${regkey}" method="post">
    Password <input type="password" name="password" autofocus class="input password"></input>
    <input type="submit" name="submit" id="submit"class="submit-button" value="Login"/>
  </form>
  <div style="margin-top:20px; font-size:80%">Not ${regkey}? <a href="/reset">Clear agent session</a> </div>
</div>
  `;
    } else {
      body = `
      <div class="card password-set">
        <div>Please enter a password to create agent keys for ${regkey}</div>
        <div style="margin-top:20px;"><b>Save this password. It cannot be reset!</b></div>
        <form style="margin-top:20px;" action="/regkey/${regkey}" method="post">
        <div style="display:flex; flex-direction:column;">
        <div id="validation"></div>
        <div><input id="pass1" type="password" name="password" autofocus placeholder="Password" class="input password"></input></div>
        <div><input id="pass2" type="password" name="password2" placeholder="Confirm Password" class="input password"></input></div>
        <div><input disabled id="submit" type="submit" name="submit" value="Create Agent Keys" class="submit-button disabled"/></div>
        </div>
        <input type="hidden" value="${regkey}" name="regkey" />
        </form>
      </div>
<script>
function checkpass(e) {
  let disabled = false
  let validationText = ""
  if (pass1.value != pass2.value) {
    disabled = true
    validationText = "Passwords don't match!"
  }
  if (!pass1 || !pass2) {
    disabled = true
  }
  const validation = document.getElementById("validation")
  validation.innerHTML = validationText
  if (disabled) {
    button.disabled = true
    button.classList.add("disabled")
  } else {
    button.disabled = false
    button.classList.remove("disabled")
  }

}
const button = document.getElementById("submit")
const pass1 = document.getElementById("pass1")
const pass2 = document.getElementById("pass2")
pass1.addEventListener("input",checkpass)
pass2.addEventListener("input",checkpass)
</script>
  `;
    }
    doSend(res, body);
    //adminWebsocket.client.close();
  } catch (e) {
    doError(res, e);
  }
};

app.get("/regkey", async (req: Request, res: Response) => {
  res.redirect("/");
});

app.post("/regkey", async (req: Request, res: Response) => {
  await handleReg(req.body.key, req, res);
});

app.get("/regkey/:key", async (req: Request, res: Response) => {
  await handleReg(req.params.key, req, res);
});

const redirecting = (regkey: string, req: Request, res: Response): number => {
  const origin = req.headers.origin;
  if (origin) {
    const hostForRegkey = instanceForRegKey(regkey);
    const found = origin.match(/([^\.]*)([0-9]+)(\.[a-z]+\.*)/);
    if (found && parseInt(found[2]) != hostForRegkey) {
      const target = `${found[1]}${hostForRegkey}${found[3]}/regkey/${regkey}`;
      console.log("REDIRECTING TO ", target);
      res.redirect(target);
      return -1;
    }
  }
  return conductorForRegKey(regkey);
};
app.get("/launcher.mac", async (req: Request, res: Response) => {
  res.sendFile(MAC_PATH);
});
app.get("/launcher.linux", async (req: Request, res: Response) => {
  res.sendFile(LINUX_PATH);
});
app.get("/launcher.windows", async (req: Request, res: Response) => {
  res.sendFile(WINDOWS_PATH);
});

app.get("/emergence.webhapp", async (req: Request, res: Response) => {
  res.sendFile(WEBHAPP_PATH);
});
app.get("/install", async (req: Request, res: Response) => {
  const network_seed = NETWORK_SEED
    ? `
  <li>
  IMPORTANT: add "${NETWORK_SEED}" as the network seed!
  </li>  
  `
    : ``;
  doSend(
    res,
    `
    <div class="card install-instructions">
    <h2>Install and Run Holochain Launcher:</h2>
    
    <p>To run Holochain and the Emergence App locally on your laptop or computer...</p>
      
    <h3>Installation</h3>

    <h4>For Mac</h4>

    <p><a href="launcher.mac"">DOWNLOAD</a> <-- Download and open this file. Then click on the round Holochain icon to run the launcher. You can choose to drag it into your Applications folder or not for easy finding later.</p>

    <h4>For Windows</h4>

    <p><a href="launcher.windows"">DOWNLOAD</a> <-- Download and run this installer. Windows will ask you to approve installing this software from the Holochain Foundation. Also, you might need to approve its traffic over your network firewall too.</p>

    <h4>For Linux</h4>

    <p><a href="launcher.linux"">DOWNLOAD</a> <-- You can download and execute this AppImage file. And put it in a place you can find it to run again later.</p>

    <h3>Execution</h3>

    <ol>
    <li>Once you've run the launcher, you'll need to create a password, and then confirm it. We cannot reset this password for you, so please remember it.</li>

    <li>Then you will want to install EMERGENCE as your first app. Go to the App Store tab, if you just installed, it may still be synchronizing data and take some moments for any apps to appear. But soon, you should find the Emergence app on the list and can click to install it. And then just accept the default settings on the next screen.</li>

    <li>You can open the Emergence app from the launcher tab by clicking its icon.</li>

    <li>The first time you open it, it has a lot of data in the schedule to synchronize, so it may take a while to gossip with other nodes to get itself updated. (For advanced users, you can go back to the launcher window, click on the settings wheel in the upper right corner. Then you can click on the three dots to open up the details about your app, and see what gossip is happwning with other agents)</li>

    <li>Now the schedule should be visible, and you can submit emergent sessions for TOMORROW.</li>
    </ol>

    <h3>Submitting Sessions</h3>

    <ol>
    <li>On the sessions tab inside the app window, you can click on the create button.</li>
    <li>The Title and Description are required. </li>
    <li>You can add tags and other leaders...</li>
    <li>Please note any required amenities... </li>
    <li>Finally, you can choose a time and place for your session.</li>
    </ol>

    <b>Other questions??</b>

    <p>Visit the Help desk at the Wagon Wheel...</p>
    
    </div>
`
  );
});

app.get(
  "/info/:conductor",
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const conductor = parseInt(req.params.conductor);
      const adminWebsocket = await getAdminWebsocket(conductor);
      const appsRaw = (await adminWebsocket.listApps({})).sort((a, b) =>
        a.installed_app_id.toLocaleLowerCase() <
        b.installed_app_id.toLocaleLowerCase()
          ? -1
          : 1
      );
      const apps = appsRaw.map((a) => {
        //@ts-ignore
        const cellId = a.cell_info["emergence"][0].provisioned.cell_id;
        //@ts-ignore
        return `<pre style="font-size:12px;">id: ${a.installed_app_id}
  DNA: ${encodeHashToBase64(cellId[0])}
Agent: ${encodeHashToBase64(cellId[1])}`;
      });
      const body = `
    <div style="text-align:left;overflow:auto;height:90%; width:90%;" class="card container">${apps.join(
      "<br>"
    )}</div>
`;
      doSend(res, body);
      //adminWebsocket.client.close();
    } catch (e) {
      doError(res, e);
      return;
    }
  }
);

app.get("/", [
  async (req: Request, res: Response, next: NextFunction) => {
    if (req.cookies["creds"]) {
      const creds = JSON.parse(req.cookies["creds"]);
      const conductor = redirecting(creds.regkey, req, res);
      if (conductor < 0) {
        return;
      }

      res.redirect("/index.html");
    } else {
      doSend(
        res,
        `
  <div class="container">
    <div class="block">
        <span>DWeb Camp 2023</span>
        <h3>Discovering Flows</h3>
        <div> Welcome. Flows are everywhere, but most of us don’t perceive them. Discovering flow means tapping into the most powerful forces around us:

        Nature. Technology. Community. You.</div>
        <div class="computer-installation">
        If you want to install the holochain-native emergence hApp on your computer instead, please follow <a href="/install"> these instructions.</a>
        </div>
    </div>
    <div class="block">
      <div class="card">
          <span class="cta-prompt">Enter your registration key to get started</span>
          <form action="/regkey/" method="post">
            <input id="regkey" placeholder="e.g. 5XyWW1Qt6" class="regkey input" type="input" name="key" autofocus></input>
            <input disabled id="submit" class="submit-button disabled" type="submit" name="submit" value="Next: Set your password"></input>
          </form>
          <img class="pwrd-by" src="/images/powered_by_holochain.png" />
      </div>
    </div>
  </div>
<script>
document.getElementById("regkey").addEventListener("input", (e)=>{
  const button = document.getElementById("submit")
  if (!e.target.value) {
    button.disabled = true
    button.classList.add("disabled")
  } else {
    button.disabled = false
    button.classList.remove("disabled")
  }
});
</script>
    `
      );
    }
  },
]);

const doError = (res: Response, err: any) => {
  if (err.message == "Socket is not open") {
    //createAdminWebsocket()
  }
  doSend(
    res,
    `
  <div class="card container" style="flex-direction:column" >
    <h4>Error!</h4>
    <div st>
      ${err.message ? err.message : JSON.stringify(err)}
    </div>
  </div>
  `
  );
};

const doSend = (res: Response, body: string, code?: string) => {
  const page = `
  <!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />

      <title>Emergence Agent Setup</title>
      ${code ? `<script>${code}</script>` : ""}
      <style>

      @font-face {
        font-family: "Poppins";
        src: url('fonts/Poppins-Regular.ttf');
        font-weight: regular;
      }
      @font-face {
        font-family: "Poppins";
        src: url('fonts/Poppins-SemiBold.ttf');
        font-weight: bold;
      }
      
      @font-face {
        font-family: "Poppins";
        src: url('fonts/Poppins-Italic.ttf');
        font-style: italic;
      }
      
      @font-face {
        font-family: "Poppins";
        src: url('fonts/Poppins-SemiBoldItalic.ttf');
        font-style: italic;
        font-weight: bold;
      }
      

        html, body {
          font-family: "Poppins", sans-serif;
          font-size: 18px;
          line-height: 1.5;
          color: #333;
          margin: 0; padding: 0;
          height: 100%; overflow: hidden; /* In general, it's a good idea to have the body take up the full viewport height and have a fixed layout with no scrollbar. Then, you can have a scrollable inner container like .pane-content to handle the overflow of the content. This approach helps keep the page structure clean and allows you to control the scrolling behavior more effectively. */
        }
        .app-info {
          width: 100%;
          height: 100%;
          overflow-y: auto;
        }
    
        .block {
          padding: 10px;
        }
    
        .card {
          min-width: 280px;
          padding: 10px; border-radius: 10px; box-shadow: 0px 10px 15px rgba(0,0,0,.25); background-color: white;
        }
    
        .submit-button {
          background: linear-gradient(129.46deg, #5833CC 8.45%, #397ED9 93.81%);
          min-height: 30px;
          min-width: 40px;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          box-shadow: 0 10px 15px rgba(0,0,0,.35);
          border-radius: 5px;
          padding: 0 10px;
          cursor: pointer;
          font-size: 16px;
          height: 50px;
          line-height: 40px;
          outline: 0;
          width: calc(100%);
          border: 0;
          margin: 10px auto;
          position: relative;
          z-index: 2;
        }

        .disabled {
          background: #aaa;
        }
    
        .pwrd-by {
          background:white; padding:8px 12px; width:90%; max-width:450px;
          position: relative;
          z-index: 0;
          display: block;
          margin: 0 auto;
        }
    
        .container {
          letter-spacing: -.008rem;
          display: flex; flex-direction: column;
          text-align: left;
          padding-top: 50px;
          margin: 0 auto;
        }
    
        .container h3 {
          font-size: 36px;
          line-height: 36px;
          margin-top: 0;
          margin-bottom: 0;
        }
    
        .cta-prompt {
          text-align: center;
          font-size: 14px;
          padding-bottom: 10px;
          display: block;
        }
    
        .input {
          font-size: 16px; padding: 8px 12px; border-radius: 3px; border: 1px solid rgba(86, 92, 109, .3);
          width: auto;
          text-align: center;
          height: 40px;
        }

        .regkey.input, .password.input {
          display: block;
          width: calc(100% - 24px);
        }

        .password.input {
          margin-bottom: 5px;
        }
    
        .computer-installation {
          display: none;
        }

        .password-set {
          max-width: 320px;
          margin: 0 auto;
        }

        .install-instructions {
          padding: 20px;
          overflow: auto;
          margin: 0 auto;
          max-width: 75%;
          max-height: 90%;
        }
    
    
        @media (min-width: 720px) {
          .container {
            flex-direction: row;
            align-items: center;
            max-width: 960px;
          }
    
          .container h3 {
            font-size: 48px;
            line-height: 48px;
          }
          
          .block {
            padding: 0 25px;
          }
    
          .computer-installation {
            margin-top:40px; font-size:14px;
            display: block;
          }
    
          .cta-prompt {
            font-size: 16px;
            min-width: 320px;
          }
        }

    
        @media (min-width: 720px) and (min-height: 500px) {
          .app-info {
            display: flex;
            align-items: center;
          }
          .container {
            padding-top: 0;
          }
        }
      </style>
    </head>
    <body style="background-image: url(/images/dweb-background.jpg);    background-size: cover;"    >
      <div class="app-info">
      ${body}
      </div>
    </body>
  </html>
  `;
  res.send(page);
};
app.get("/fail", async (req: Request, res: Response) => {
  try {
    throw "test error";
  } catch (e) {
    doError(res, e);
  }
});

// const WORKDIR_DIR = "/home/eric/code/metacurrency/holochain/hc-multiplexer/multiplexer/workdir"

// try {
//   let cmd = `echo "pass" | lair-keystore -r ${WORKDIR_DIR}/keystore server --piped`
//   let output = myExec(cmd)
//   cmd = `echo "pass" | holochain --piped -c  ${WORKDIR_DIR}/conductor-config.yaml`
//   output = myExec(cmd)
//   console.log("holochain started holochian:", output )

// } catch (e) {
//   console.log("error starting holochian:", e )
// }

const REAL_WS_COUNT: number = 10;

const realWsAll: Array<Set<WebSocket>> = [...Array(CONDUCTOR_COUNT)].map(
  () => new Set()
);
const realWsQueue: Array<Array<WebSocket>> = [...Array(CONDUCTOR_COUNT)].map(
  () => []
);

async function realWsGet(conductor: number): Promise<WebSocket> {
  while (realWsAll[conductor].size < REAL_WS_COUNT) {
    const realWs = await realWsConnect(conductor);
    realWsAll[conductor].add(realWs);
    realWsQueue[conductor].unshift(realWs);
  }
  const realWs = realWsQueue[conductor].shift();
  if (!realWs) {
    throw new Error("no real websockets available");
  }
  realWsQueue[conductor].push(realWs);
  return realWs;
}

function realWsDelete(conductor: number, realWs: WebSocket) {
  realWsAll[conductor].delete(realWs);
  realWsQueue[conductor].splice(0, realWsQueue[conductor].length);
  for (const realWs of realWsAll[conductor].values()) {
    realWsQueue[conductor].unshift(realWs);
  }
}

let globWss: Array<WebSocketServer | null> = [...Array(CONDUCTOR_COUNT)].map(
  () => null
);
const locWsAll: Array<Set<WebSocket>> = [...Array(CONDUCTOR_COUNT)].map(
  () => new Set()
);
const reqReg: Array<Map<number, WebSocket>> = [...Array(CONDUCTOR_COUNT)].map(
  () => new Map()
);

function mparse(d: Buffer | ArrayBuffer | Buffer[]): {
  type: string;
  id: number;
} {
  const out = (d: { type: string; id: number }) => {
    return { type: d.type, id: d.id };
  };
  if (d instanceof Uint8Array) {
    return out(msgpack.decode(d));
  } else if (d instanceof ArrayBuffer) {
    return out(msgpack.decode(new Uint8Array(d)));
  } else {
    throw new Error("PANIC BAD BUF TYPE");
  }
}

function realAppPortForInterface(conductor: number) {
  return REAL_APP_PORT_FOR_INTERFACE + conductor;
}

async function realWsConnect(conductor: number): Promise<WebSocket> {
  return await new Promise((resolve, reject) => {
    const ws = new WebSocket(
      `ws://127.0.0.1:${realAppPortForInterface(conductor)}`
    );
    ws.on("error", (err) => {
      console.error("FATAL!! REAL APP WEBSOCKET ERROR", err);
      reject(err);
    });
    ws.on("close", () => {
      console.error("FATAL!! REAL APP WEBSOCKET CLOSED");
    });
    ws.on("open", () => {
      resolve(ws);
    });
    ws.on("message", (data, binary) => {
      const { type, id } = mparse(data);
      if (type === "response") {
        const socket = reqReg[conductor].get(id);
        if (socket) {
          reqReg[conductor].delete(id);
          socket.send(data, { binary: true }, (err) => {
            if (err) {
              locWsAll[conductor].delete(socket);
            }
          });
        }
      } else if (type === "request") {
        // we don't make out requests
        console.error("UNEXPECTED OUT REQUEST!!");
      } else {
        // must be a signal, send it to everyone
        for (const locWs of locWsAll[conductor].values()) {
          locWs.send(data, { binary }, (err) => {
            if (err) {
              locWsAll[conductor].delete(locWs);
            }
          });
        }
      }
    });
  });
}

function makeWsServer(i: number): WebSocketServer {
  const wss = new WebSocketServer({
    port: APP_PORT_FOR_INTERFACE + i,
  });

  wss.on("connection", (locWs) => {
    console.log(`INCOMING WS CONNECTION FOR CONDUCTOR `, i);
    locWs.on("error", console.error.bind(console, "pool-app-err"));
    locWs.on("message", (data, binary) => {
      const { type, id } = mparse(data);
      if (type === "response") {
        // we don't respond to requests from hc
        console.error("UNEXPECTED IN RESPONSE!!");
      } else if (type === "request") {
        reqReg[i].set(id, locWs);
        // TODO - timeout
        realWsGet(i).then((realWs) => {
          realWs.send(data, { binary }, (err) => {
            if (err) {
              realWsDelete(i, realWs);
            }
          });
        });
      } else {
        // who knows what this is??
        realWsGet(i).then((realWs) => {
          realWs.send(data, { binary }, (err) => {
            if (err) {
              realWsDelete(i, realWs);
            }
          });
        });
      }
    });
    locWsAll[i].add(locWs);
  });
  return wss;
}

globWss = [];
for (let i = 0; i < CONDUCTOR_COUNT; i += 1) {
  try {
    globWss.push(makeWsServer(i));
  } catch (e: any) {
    console.log(`Error making WsServer: ${e.message}.`);
  }

  try {
    const adminWebsocket = await getAdminWebsocket(i);
    console.log(`Starting app interface on port ${realAppPortForInterface(i)}`);
    await adminWebsocket.attachAppInterface({
      port: realAppPortForInterface(i),
    });
  } catch (e: any) {
    console.log(`Error attaching app interface: ${e.message}.`);
  }
}

app.use("/", express.static(HAPP_UI_PATH));

app.get("/reset", (req: Request, res: Response): void => {
  res.clearCookie("creds");
  res.redirect("/");
});
app.listen(PORT, "0.0.0.0", (): void => {
  console.log("SERVER IS UP ON PORT:", PORT);
});
