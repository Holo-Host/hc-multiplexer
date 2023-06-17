#!/usr/bin/env node

import express, { Application, Request, Response, NextFunction } from "express";
import {
  AdminWebsocket,
  AgentPubKey,
  GrantedFunctionsType,
  CellId,
  GrantedFunctions,
  encodeHashToBase64,
} from "@holochain/client";
// import { HoloHash } from '@whi/holo-hash';
import blake2b from "blake2b";
//import * as ed25519 from "@noble/ed25519";
import nacl from "tweetnacl";

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

const configPathFromDotHC = () => {
  let data = fs.readFileSync(".hc", "utf8");
  data = data.substring(0, data.length - 1);

  return `${data}/conductor-config.yaml`;
};

const CONDUCTOR_CONFIG_PATH =
  process.env.CONDUCTOR_CONFIG_PATH || configPathFromDotHC();
const CONDUCTOR_CONFIG = fs.readFileSync(CONDUCTOR_CONFIG_PATH, "utf8");
const adminPortFromConfig = () => {
  const result = CONDUCTOR_CONFIG.match(
    /driver:\W+type: websocket\W+port: ([0-9]+)/m
  );
  if (!result) throw "Unable to find admin port in config";
  return result[1];
};
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const HC_ADMIN_PORT = process.env.HC_ADMIN_PORT || adminPortFromConfig();
const HAPP_UI_PATH = process.env.HAPP_UI_PATH || "./";
const HAPP_PATH = process.env.HAPP_PATH || "";
const WEBHAPP_PATH = process.env.WEBHAPP_PATH || "";
const LAIR_CLI_PATH = process.env.LAIR_CLI_PATH || "";
const NETWORK_SEED = process.env.NETWORK_SEED || "";

const INSTANCE_COUNT = parseInt(
  process.env.INSTANCE_COUNT ? process.env.INSTANCE_COUNT : "1"
);
const MY_INSTANCE_NUM = parseInt(
  process.env.MY_INSTANCE_NUM ? process.env.MY_INSTANCE_NUM : "1"
);
const APP_PATH_FOR_CLIENT = process.env.APP_PATH_FOR_CLIENT || "appwebsocket";
const APP_PORT_FOR_INTERFACE: number = parseInt(
  process.env.APP_PORT_FOR_INTERFACE || "3030"
);

const instanceForRegKey = (regkey: string): number => {
  console.log("XXX", regkey, Buffer.from(regkey)[0], INSTANCE_COUNT)
  return (Buffer.from(regkey)[0] % INSTANCE_COUNT) + 1;
};

const getLairSocket = () => {
  // prefer getting the url from lair-keystore directly
  if (process.env.LAIR_PATH && process.env.LAIR_WORKING_DIRECTORY) {
    const cmd = `${process.env.LAIR_PATH} --lair-root ${process.env.LAIR_WORKING_DIRECTORY} url`;

    try {
      const output = myExec(cmd);
      return output;
    } catch (e) {
      console.log("Error when while attempting to read lair-keystore url: ", e);
    }
  }

  // fallback to parsing the conductor config
  const result = CONDUCTOR_CONFIG.match(/.*connection_url: (.*)/);
  if (!result) throw "Unable to find connectuion URL";
  return result[1];
};

const uint8ToBase64 = (arr: Uint8Array) => Buffer.from(arr).toString("base64");
const base64ToUint8 = (b64: string) =>
  Uint8Array.from(Buffer.from(b64, "base64"));

const deriveSigningKeys = async (
  seed: string
): Promise<[nacl.SignKeyPair, AgentPubKey]> => {
  //const interim = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
  //  const privateKey = await blake2b(interim.length).update(Buffer.from(seed)).digest('binary')
  //  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  //  const keyPair = { privateKey, publicKey };

  const interim = Buffer.from([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ]);
  const seedBytes = await blake2b(interim.length)
    .update(Buffer.from(seed))
    .digest("binary");

  const keyPair = nacl.sign.keyPair.fromSeed(seedBytes);

  const signingKey = new Uint8Array(
    [132, 32, 36].concat(...keyPair.publicKey).concat(...[0, 0, 0, 0])
  );
  return [keyPair, signingKey];
};

const credsToJson = (creds: any, installed_app_id: string, regkey: string) => {
  return JSON.stringify({
    installed_app_id,
    regkey,
    appPath: APP_PATH_FOR_CLIENT,
    creds: {
      capSecret: uint8ToBase64(creds.capSecret),
      keyPair: {
        publicKey: uint8ToBase64(creds.keyPair.publicKey),
        secretKey: uint8ToBase64(creds.keyPair.secretKey),
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

const makeKey = async (adminWebsocket: AdminWebsocket, seedStr: string) => {
  const cmd = `echo "pass" | ${LAIR_CLI_PATH} import-seed-string "${getLairSocket()}" "${seedStr}"`;

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


const genCredsForPass = async (
  regkey: string,
  password: string
) => {
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
  return creds
}



const setCredsForPass = async (
  regkey: string,
  password: string,
  installed_app_id: string,
  res: Response,
) => {
  const creds = await genCredsForPass(regkey, password)

  const credsJSON = credsToJson(creds, installed_app_id, regkey);
  res.cookie("creds", credsJSON);
  res.redirect("/");
};

const installedAppId = (regKey: string) => {
  return `emergence-${regKey}`;
};

const installAgent = async (adminWebsocket :AdminWebsocket, regkey: string, password:string) => {
  const installed_app_id = installedAppId(regkey);
  const agent_key = await makeKey(
    adminWebsocket,
    `${password}-${regkey}`
  );
  if (agent_key) {
    const appInfo = await adminWebsocket.installApp({
      agent_key,
      path: HAPP_PATH,
      installed_app_id,
      membrane_proofs: {},
      network_seed: NETWORK_SEED,
    },30000);
    await adminWebsocket.enableApp({ installed_app_id });

    console.log("installing", regkey, appInfo);
    // @ts-ignore
    const { cell_id } = appInfo.cell_info["emergence"][0]["provisioned"];

    const creds = await genCredsForPass(regkey, password)

    await grantUIPassword(
      adminWebsocket,
      cell_id,
      creds.capSecret,
      { [GrantedFunctionsType.All]: null },
      creds.signingKey
    );
  } else {
    throw(`error creating agent_key`);
  }
}

app.post("/regkey/:key", async (req: Request, res: Response) => {
  const regkey = req.params.key;
  if (redirecting(regkey, req, res)) {
    return;
  }

  try {
    const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`;
    const adminWebsocket = await AdminWebsocket.connect(url);

    const apps = await adminWebsocket.listApps({});
    const installed_app_id = installedAppId(regkey);
    const appInfo = apps.find(
      (info) => info.installed_app_id == installed_app_id
    );

    if (!appInfo) {
      await installAgent(adminWebsocket, regkey, req.body.password)
    }
    await setCredsForPass(
      regkey,
      req.body.password,
      installed_app_id,
      res,
    );
    adminWebsocket.client.close();
  } catch (e) {
    doError(res, e);
  }
});

const handleReg = async (regkey: string, req: Request, res: Response) => {
  if (redirecting(regkey, req, res)) {
    return;
  }

  try {
    const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`;
    const adminWebsocket = await AdminWebsocket.connect(url);
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
    adminWebsocket.client.close();
  } catch (e) {
    doError(res, e);
  }
};

app.get("/gen/:count", async (req: Request, res: Response) => {
  const count = parseInt(req.params.count)

  try {
    const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`;
    const adminWebsocket = await AdminWebsocket.connect(url);
    // const appsRaw = (await adminWebsocket.listApps({})).sort((a, b) =>
    //   a.installed_app_id.toLocaleLowerCase() <
    //   b.installed_app_id.toLocaleLowerCase()
    //     ? -1
    //     : 1
    // );
    for (let i=1; i<= count; i+=1) {
      await installAgent(adminWebsocket, `agent${i}`, `${i}`)
    }
    const body = `
    <h3>generated ${count} instances
`;
    doSend(res, body);
    adminWebsocket.client.close();
  } catch (e) {
    doError(res, e);
    return;
  }
});

app.get("/regkey", async (req: Request, res: Response) => {
  res.redirect("/");
});

app.post("/regkey", async (req: Request, res: Response) => {
  await handleReg(req.body.key, req, res);
});

app.get("/regkey/:key", async (req: Request, res: Response) => {
  await handleReg(req.params.key, req, res);
});

// const happ = function (_req: Request, res: Response) {
//   res.sendFile(path.join(__dirname, '/index.html'));
// }

const redirecting = (regkey: string, req: Request, res: Response): boolean => {
  const origin = req.headers.origin;
  if (origin) {
    const hostForRegkey = instanceForRegKey(regkey);
    const found = origin.match(/(.*)([0-9]+)(\..*\.*)/);
    console.log("hostForRegkey", hostForRegkey)
    console.log("found", found)

    if (found && parseInt(found[2]) != hostForRegkey) {
      const target = `${found[1]}${hostForRegkey}${found[3]}/regkey/${regkey}`;
      console.log("REDIRECTING TO ", target);
      res.redirect(target);
      return true;
    }
  }
  return false;
};
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
      <h3>Launcher Install Instructions:</h3>
      <ol style="text-align: left">
      <li>
      Download the the <a href="https://drive.switch.ch/index.php/s/UH1kPtKF6nECyAy">Launcher for your platfrom</a>
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
    </div>
`
  );
});

app.get("/info", async (req: Request, res: Response, next: NextFunction) => {
  try {
    const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`;
    const adminWebsocket = await AdminWebsocket.connect(url);
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
    <div style="text-align:left;overflow:auto;height:90%; width:90%;" class="card container">${apps.join("<br>")}</div>
`;
    doSend(res, body);
    adminWebsocket.client.close();
  } catch (e) {
    doError(res, e);
    return;
  }
});

app.get("/", [
  async (req: Request, res: Response, next: NextFunction) => {
    if (req.cookies["creds"]) {
      const creds = JSON.parse(req.cookies["creds"]);
      if (redirecting(creds.regkey, req, res)) {
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
  doSend(
    res,
    `
  <div style="border: solid 1px; border-radius:10px;padding:0 20px 20px 20px;min-width:300px;">
  <h4>Error!</h4>
  ${err.message ? err.message : JSON.stringify(err)}
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
  

      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">      \
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Emergence Agent Setup</title>
      ${code? `<script>${code}</script>`:""}
      <style>
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
          margin: 0 auto;
          max-width: 720px;
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

try {
  const url = `ws://127.0.0.1:${HC_ADMIN_PORT}`;
  const adminWebsocket = await AdminWebsocket.connect(url);
  console.log(`Starting app interface on port ${APP_PORT_FOR_INTERFACE}`);
  await adminWebsocket.attachAppInterface({ port: APP_PORT_FOR_INTERFACE });
  adminWebsocket.client.close();
} catch (e) {
  // @ts-ignore
  console.log(`Error attaching app interface: ${e.data.data}.`);
}

app.use("/", express.static(HAPP_UI_PATH));

app.get("/reset", (req: Request, res: Response): void => {
  res.clearCookie("creds");
  res.redirect("/");
});
app.listen(PORT, "0.0.0.0", (): void => {
  console.log("SERVER IS UP ON PORT:", PORT);
});
