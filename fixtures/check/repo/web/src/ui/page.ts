import { query } from "../db/client";
import React from "react";
// import { secret } from "../db/secret";
/* require("../db/client") */
const note = "require('../db/client')";
const pattern = /import\("..\/db\/client"\)/;

export async function load(name: string) {
  const mod = await import(name);
  return [query, React, note, pattern, mod, `${name}/../db/client`];
}
