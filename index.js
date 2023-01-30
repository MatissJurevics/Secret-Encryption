import express from "express";
import bodyParser from "body-parser";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import pkg from "crypto-js";
const { SHA256, AES, enc } = pkg;

const app = express();
const PORT = 3000;
const __dirname = dirname(fileURLToPath(import.meta.url));

const file = join(__dirname, "/db.json");
const adapter = new JSONFile(file);
const db = new Low(adapter);
await db.read();
db.data ||= {
  started: false,
  people: {},
  logs: [],
  passwords: ["", "", ""],
  masterPass: "",
};
let { started, people, passwords, masterPass, logs } = db.data;

const generatePasswords = async () => {
  let master = "";
  for (let i = 0; i < 3; i++) {
    let validChars = "zxcvbnmasdfghjklqwertyuiop!£$^&*";
    let pass = "";
    for (let j = 0; j < 12; j++) {
      pass += validChars[Math.floor(Math.random() * validChars.length)];
    }
    passwords[i] = SHA256(pass).toString(enc.Hex);
    master += `${pass}-`;
    console.log(`User ${i}: ${pass}`);
  }
  for (let i = 0; i < 4; i++) {
    let validChars = "zxcvbnmasdfghjklqwertyuiop!£$^&*";
    master += validChars[Math.floor(Math.random() * validChars.length)];
  }
  db.data.masterPass = SHA256(master).toString(enc.Hex);
  console.log(`Master : ${master}`);
  db.data.started = true;
  await db.write();
};
if (!started) {
  generatePasswords();
}
db.write();

await db.write();

app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.sendFile(join(__dirname, "/index.html"));
});

app.post("/", async (req, res) => {
  const { name, info, password } = req.body;
  if (!passwords.includes(SHA256(password).toString(enc.Hex))) {
    res.redirect("/?status=forbidden");
  }
  let hashedPass = SHA256(password).toString(enc.Hex);
  let encInfo = AES.encrypt(info, password).toString();
  people[name] ||= [];
  people[name].push(`${passwords.indexOf(hashedPass)}-${encInfo}`);
  logs.push(
    `User ${
      passwords.indexOf(hashedPass) + 1
    } has added "${encInfo} at ${name}-${people[name].indexOf(encInfo)}"`
  );
  await db.write();
  res.redirect("/?status=success");
});

app.get("/decrypt", (req, res) => {
  let name = req.query.name,
    password = req.query.password,
    index = req.query.index;
  let text = people[name][Number(index)];
  let cyphertext = text.split("-")[1];
  if (passwords[Number(text.split("-")[0])] != SHA256(password)) {
    res.redirect("/?status=invalidPass");
  }
  let plaintext = AES.decrypt(cyphertext, password).toString(enc.Utf8);
  res.send(plaintext);
});

app.get("/decryptall", (req, res) => {
  let data = {};
  let { password } = req.query;
  console.log(password);
  if (SHA256(password) != masterPass) {
    res.send("Invalid Password");
  }
  let passArr = password.split("-");
  for (let person in people) {
    data[person] ||= [];
    console.log(person);
    for (let val in people[person]) {
      let string = people[person][val];
      let cyphertext = string.split("-")[1];
      let index = Number(string.split("-")[0]);
      console.log(passArr[index]);
      let plaintext = AES.decrypt(cyphertext, passArr[index]).toString(
        enc.Utf8
      );
      console.log(plaintext);
      data[person].push(plaintext);
    }
  }
  res.send(data);
});

app.get("/browse", async (req, res) => {
  res.send(people);
});
app.listen(PORT, () => {
  console.log("listening on port " + PORT);
});
