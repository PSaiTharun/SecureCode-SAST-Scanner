// Safer illustrative patterns
function render(req,res) { res.render('hello',{name:req.query.name}); }
function search(db,term) { return db.query('SELECT * FROM items WHERE name=?',[term]); }
function launch(input) { if (!['status','version'].includes(input)) throw Error('bad input'); execFile('tool',['--name',input]); }
function calc(data) { return JSON.parse(data); }
