// Test cases for js-code-from-text. Run: opengrep scan --test rules/
// Written before the rule. Text that is run as code: eval, new Function, setTimeout with a string, Node's vm.
const vm = require('vm');
const express = require('express');
const app = express();

// --- eval with anything but a literal ---

app.post('/calc', (req, res) => {
  // ruleid: js-code-from-text
  res.json({ result: eval(req.body.expression) });
});

function profileName(user) {
  const code = user.username.substring(2, user.username.length - 1);
  // ruleid: js-code-from-text
  return eval(code);
}

function onMessage(msg) {
  // ruleid: js-code-from-text
  window.eval(msg.data);
  // ruleid: js-code-from-text
  globalThis.eval(`run(${msg.data})`);
}

// --- new Function with a body built from data ---

function makeFilter(rule) {
  // ruleid: js-code-from-text
  return new Function('row', 'return ' + rule.expr);
}

function makeFormula(f) {
  // ruleid: js-code-from-text
  return Function('x', f.body);
}

// --- setTimeout or setInterval given a string ---

function later(name) {
  // ruleid: js-code-from-text
  setTimeout('greet("' + name + '")', 100);
  // ruleid: js-code-from-text
  setInterval(`tick(${name})`, 1000);
}

// --- Node vm: it is not a sandbox ---

app.post('/b2b', (req, res) => {
  const sandbox = { safeEval: require('notevil'), orderLinesData: req.body.orderLinesData };
  vm.createContext(sandbox);
  // ruleid: js-code-from-text
  vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 });
  res.end();
});

app.post('/script', (req, res) => {
  // ruleid: js-code-from-text
  const out = vm.runInNewContext(req.body.script, {});
  // ruleid: js-code-from-text
  const s = new vm.Script(req.body.source);
  // ruleid: js-code-from-text
  vm.runInThisContext(`(${req.body.fn})`);
  res.json({ out, s });
});

// --- Not run as code ---

function safe(text, rows) {
  // ok: js-code-from-text
  const data = JSON.parse(text);
  // ok: js-code-from-text
  const two = eval('1 + 1');
  // ok: js-code-from-text
  window.eval('init()');
  // ok: js-code-from-text
  const dynamicImport = new Function('specifier', 'return import(specifier)');
  // ok: js-code-from-text
  setTimeout(() => rows.push(data), 100);
  // ok: js-code-from-text
  setTimeout(refresh, 1000);
  // ok: js-code-from-text
  setInterval(function () { refresh(); }, 1000);
  return [two, dynamicImport];
}

function parseInVm(data, sandbox) {
  // vm used only to put a time limit on a parser: the code is fixed and does not evaluate the data.
  // ok: js-code-from-text
  return vm.runInContext('JSON.stringify(yaml.load(data))', sandbox, { timeout: 2000 });
}

async function browser(page, el) {
  // ok: js-code-from-text
  await page.evaluate(() => document.title);
  // ok: js-code-from-text
  const v = el.evaluate('//a', el);
  return v;
}

// Redis EVAL runs a Lua script on the Redis server, not JavaScript.
async function counter(redisClient, luaScript, key) {
  // ok: js-code-from-text
  return redisClient.eval(luaScript, 1, key);
}

// A compiled vm.Script is run with a context, not with code.
function runCompiled(ctx) {
  const script = new vm.Script('total + 1');
  // ok: js-code-from-text
  return script.runInContext(ctx);
}

function laterParts(name, fnName) {
  // ruleid: js-code-from-text
  setTimeout('greet' + name, 10);
  // ruleid: js-code-from-text
  setTimeout(fnName + '()', 10);
}

// --- A function given to setTimeout is not a string, even if it builds strings inside ---
function poll(el, name) {
  // ok: js-code-from-text
  setTimeout(() => { el.textContent = 'Hi ' + name; }, 0);
  // ok: js-code-from-text
  setInterval(function () { el.title = `${name} is online`; }, 1000);
}

// Other functions given a built string are not timers.
function logs(name) {
  // ok: js-code-from-text
  console.log('Hi ' + name);
  // ruleid: js-code-from-text
  window.setTimeout('show(' + name + ')', 5);
}
