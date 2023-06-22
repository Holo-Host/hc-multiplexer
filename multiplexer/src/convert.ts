#!/usr/bin/env node
import { raw } from "express";
import * as fs from "fs";

const SESSION_TYPES= ["Session","Children Time","Community Time","Creativity Time","Dining","Chill & Relax","Mind-Body-Nature","Panel / Discussion","Prep","Talk","Workshop"]
const NULL_HASHB64 = "uhCkk______________________"

let e = fs.readFileSync("emergence.json", "utf8");
const ex = JSON.parse(e)
let p = fs.readFileSync("proxys.json", "utf8");
const proxys = JSON.parse(p)

let data = fs.readFileSync("sessions.txt", "utf8");
let rawlines = data.split(/\n/)
const lines:Array<any> = []
for (let i=0;i<rawlines.length;i+=1) {
    const l = rawlines[i]
    if (!l) continue
    let [type,subType,title,description,leaders,otherHost,tags,venue,span,timestamp,minutes,start,end] = l.split("\t")
    if (leaders == undefined) {
        throw(`leaders undefined for ${l}`)
    }
    const hosts = leaders.split(/; +/)
    const hostList = []
    for (const h of hosts) {
        if (h) {
            //@ts-ignore
            if (!proxys.find(p=>p.original_hash==h)) {
                throw(`couldn't find leader: ${h}`)
            }
            hostList.push(`{"type": "ProxyAgent","hash": "${h}"}`)
        }
    }

    const hostsJSON = hostList.join(",")

    const re = /<a[^>]*href="([^"]+)"[^>]*>([^>]+)<\/a>/

    let slot = ""
    if (venue){
        // @ts-ignore
        const spaceIndex = ex.spaces.findIndex(s=> s.entry.name == venue && s.entry.tags[0]== 'curated')
        if (spaceIndex == -1) {
            throw(`cant find ${venue}`)
        }
        const space = ex.spaces[spaceIndex]
        slot = `
        {
            "timestamp": 1686181336414519,
            "src": "${i}",
            "dst": "${space.original_hash}",
            "content": {
                "path": "session.slot",
                "data": "{\\"start\\":${timestamp},\\"duration\\":${minutes},\\"tags\\":[\\"curated\\"]}"
            }
        }`
        const spaceRelJSON = `                {
            "timestamp": 1687303314574768,
            "src": "${space.original_hash}",
            "dst": "${i}",
            "content": {
                "path": "space.sessions",
                "data": "{\\"start\\":${timestamp},\\"duration\\":${minutes},\\"tags\\":[\\"curated\\"]}"
            }
        }`
        const spaceRel = JSON.parse(spaceRelJSON)
        ex.spaces[spaceIndex].relations.push(spaceRel)
    } else {
        slot = `
        {
            "timestamp": 1686181336414519,
            "src": "${i}",
            "dst": "${NULL_HASHB64}",
            "content": {
                "path": "session.slot",
                "data": "{\\"start\\":${timestamp},\\"duration\\":${minutes},\\"tags\\":[\\"curated\\"]}"
            }
        }`

    }
    const session_type = SESSION_TYPES.findIndex(s=>s==type)
    if (session_type == -1) {
        throw(`Couldn't find session type ${type}`)
    }
    description = description.replace(re, '[$2]($1)');
    lines.push( `
    {
        "original_hash": "${i}",
        "entry": {
            "key": "KEY${i}",
            "session_type": ${session_type},
            "title": ${JSON.stringify(title)},
            "description": ${JSON.stringify(description)},
            "leaders": [${hostsJSON}],
            "smallest": 2,
            "largest": 100,
            "duration": ${minutes},
            "amenities": 0,
            "trashed": false,
            "tags": [${tags.split(/, */).map(t=>t?JSON.stringify(t):"").join(",")}]
        },
        "relations": [${slot}]
    }
    `)
}

let converted = lines.join()
//fs.writeFileSync('converted.json', converted);
const sessions = JSON.parse(`[${converted}]`)

ex.sessions = sessions
ex.proxyAgents = proxys

fs.writeFileSync('converted.json', JSON.stringify(ex));