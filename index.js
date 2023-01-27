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
  people: {},
  logs: [],
  passwords: [
    "9771b135e7efaa0a86c0b9ed5aebce6d625657f51d4ab1ec316f636828e4803b", // 2jf8s!   // user 1
    "c9eb6302327f438d412093fd3255a081d3982089c798f6535e39f5750a0c8a2c", // v8t39b?  // user 2
    "a3cf57dbdce11e002d84a3b705a76bb5ae70c40b3aea01a6ba98ad54abdcc945", // od4?5x   // user 3
  ],
  masterPass:
    "948a68ecca850a0a61ff6eeb369bac520d9c89c64d73ed9b57f0b48d36b4a16c",
};
db.write();
const { people, passwords, masterPass, logs } = db.data;

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
    let data = {}
  let {password} = req.body;
  if (SHA256(password) != masterPass) {
    res.send("Invalid Password");
  }
  let passArr = password.split("-");
  for (let person in people) {
    data[person] ||= []
    console.log(person)
    for (let val in people[person]) {
        let string = people[person][val]
        let cyphertext = string.split('-')[1]
        let index = Number(string.split("-")[0])
        console.log(passArr[index])
        let plaintext = AES.decrypt(cyphertext, passArr[index]).toString(enc.Utf8);
        console.log(plaintext)
        data[person].push(plaintext);
    }
  }
  res.send(data)
});

app.get("/browse", async (req, res) => {
  res.send(people);
});
app.listen(PORT, () => {
  console.log("listening on port " + PORT);
});
