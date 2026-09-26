import fs from "fs";
const base="https://accesslayer-lexhack.floot.app";
const assets=[
  "/_assets/index-DiSNo4Kj.js",
  "/_assets/_index-B_5LUuSv.js",
  "/_assets/workspace-C8o-g74K.js",
  "/_assets/vendor-BumYcPb0.js",
  "/_assets/_index-DwXASWdy.css",
  "/_assets/workspace-CfAix4oN.css"
];
for(const p of assets){
  const r=await fetch(base+p);
  const b=Buffer.from(await r.arrayBuffer());
  const out="C:/Users/swarr/aeria-codex/recovered-build/"+p.split("/").pop();
  fs.writeFileSync(out,b);
  console.log(r.status,b.length,out);
}
const html=await fetch(base).then(r=>r.text());
fs.writeFileSync("C:/Users/swarr/aeria-codex/recovered-build/index.html",html);
console.log("html",html.length);