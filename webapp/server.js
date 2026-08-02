// Aplicacao Express DELIBERADAMENTE VULNERAVEL.
//
// ATENCAO: existe apenas para validar a deteccao multi-linguagem do CodeQL na POC
// de migracao do SAST. Nao copie, nao importe, nao use como referencia.
//
// Cada rota aciona uma query especifica da suite javascript-security-extended.

const express = require('express');
const fs = require('fs');
const cp = require('child_process');
const app = express();

// js/path-injection: caminho do arquivo vem direto da query string.
app.get('/download', (req, res) => {
  const file = req.query.file;
  const content = fs.readFileSync(file, 'utf8');
  res.send(content);
});

// js/command-line-injection: input concatenado num comando de shell.
app.get('/ping', (req, res) => {
  const host = req.query.host;
  cp.exec('ping -c 1 ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

// js/reflected-xss: input refletido no HTML sem escaping.
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.setHeader('Content-Type', 'text/html');
  res.send('<h1>Ola, ' + name + '</h1>');
});

// js/code-injection: avaliacao dinamica de expressao controlada pelo usuario.
app.get('/calc', (req, res) => {
  const expr = req.query.expr;
  res.send(String(eval(expr)));
});

// js/server-side-unvalidated-url-redirection: destino do redirect vem do cliente.
app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

// js/sql-injection: query montada por concatenacao de string.
const mysql = require('mysql');
const db = mysql.createConnection({ host: 'localhost', user: 'app', database: 'app' });

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = ' + id, (err, rows) => {
    res.json(rows);
  });
});

app.listen(3000);
