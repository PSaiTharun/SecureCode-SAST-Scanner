// Training fixture only
const api_key = "DEMO_ONLY_REPLACE_ME_12345";
function render(req, res) { res.send("<h1>" + req.query.name + "</h1>"); }
function search(db, term) { return db.query("SELECT * FROM items WHERE name='" + term); }
function launch(input) { exec("tool --name " + input); }
function calc(code) { return eval(code); }
