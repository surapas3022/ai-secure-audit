// Test cases for js-html-from-user-text. Run: opengrep scan --test rules/
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// Comment board: other people's comments rendered as HTML.
function renderComments(list, comments) {
  // ruleid: js-html-from-user-text
  list.innerHTML = comments.map((c) => `<li><b>${c.authorName}</b> ${c.text}</li>`).join('');
}

// Shop reviews, destructured fields.
function renderReviews(box, reviews) {
  // ruleid: js-html-from-user-text
  box.innerHTML = reviews.map(({ title, stars }) => `<h3>${title}</h3><span>${stars}</span>`).join('');
}

// Chat: a message added at the end.
function addMessage(log, msg) {
  // ruleid: js-html-from-user-text
  log.insertAdjacentHTML('beforeend', '<p>' + msg.message + '</p>');
}

// Profile: a field shown on its own.
function showBio(el, profile) {
  // ruleid: js-html-from-user-text
  el.innerHTML = profile.bio;
}

// A search box echoed back.
function echoSearch(out, input) {
  // ruleid: js-html-from-user-text
  out.innerHTML = `No results for <i>${input.value}</i>`;
}

// jQuery.
function renderTask(task) {
  // ruleid: js-html-from-user-text
  $('#tasks').append(`<li>${task.description}</li>`);
}

// Server page built from the query string.
app.get('/hello', (req, res) => {
  // ruleid: js-html-from-user-text
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});

// Escaped first.
function renderCommentsSafe(list, comments) {
  // ok: js-html-from-user-text
  list.innerHTML = comments.map((c) => `<li><b>${esc(c.authorName)}</b> ${esc(c.text)}</li>`).join('');
}

// Set as text, not HTML.
function showBioSafe(el, profile) {
  // ok: js-html-from-user-text
  el.textContent = profile.bio;
}

// Only fixed markup, numbers and the app's own helpers.
function renderCounts(bar, s, icon) {
  // ok: js-html-from-user-text
  bar.innerHTML = `${icon('alert')}<span>${s.total} votes</span><span>${s.percent}%</span>`;
}

// A class name or tag name is not text people type.
function renderBadge(el, item) {
  // ok: js-html-from-user-text
  el.innerHTML = `<span class="${item.className}">${item.count}</span>`;
}

// lit-html escapes values in its html tag.
function renderLit(el, user) {
  // ok: js-html-from-user-text
  el.innerHTML = html`<p>${user.name}</p>`;
}

// Cleared.
function clear(el) {
  // ok: js-html-from-user-text
  el.innerHTML = '';
}

// React.
function Post({ post }) {
  // ruleid: js-html-from-user-text
  return <div className="body" dangerouslySetInnerHTML={{ __html: post.content }} />;
}

function PostSafe({ post }) {
  // ok: js-html-from-user-text
  return <div className="body" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.content) }} />;
}

function Static() {
  // ok: js-html-from-user-text
  return <div dangerouslySetInnerHTML={{ __html: '<b>fixed</b>' }} />;
}

function Text({ post }) {
  // ok: js-html-from-user-text
  return <div>{post.content}</div>;
}

// The app's own tab labels and a dialog body the caller built: bare variables are not matched.
function renderTabs(root, TABS, body) {
  // ok: js-html-from-user-text
  root.innerHTML = TABS.map(([k, label]) => `<button data-tab="${k}">${label}</button>`).join('') + `<div>${body}</div>`;
}

// --- Known false findings (todook): the rule judges by the field's name, so it cannot tell these from user text ---
// A boolean flag named text, put in an ARIA state attribute that only takes true or false.
function toggles(c) {
  // todook: js-html-from-user-text
  return `<button aria-pressed="${c.text}">text</button><button aria-checked="${c.title}">title</button>`;
}

// Labels the app wrote itself, in an array of object literals in the same file.
const STEPS = [{ title: 'Name the event', go: 'Open settings' }, { title: 'Add topics', go: 'Open topics' }];
function steps() {
  // todook: js-html-from-user-text
  return STEPS.map((x) => `<li><b>${x.title}</b><button>${x.go}</button></li>`).join('');
}

// --- One template with nested templates is one finding, at the line where it starts ---
function card(u, x) {
  // ruleid: js-html-from-user-text
  return `<section class="card">
    <p>${x.on ? `<b>on</b>` : ''}</p>
    ${x.more ? `<div class="more">more</div>` : ''}
    <i>${u.name}</i>
  </section>`;
}

// --- Angular: bypassSecurityTrust* turns Angular's own escaping off for the value ---
class SearchResult {
  show(sanitizer, row, queryParam) {
    // ruleid: js-html-from-user-text
    row.description = sanitizer.bypassSecurityTrustHtml(row.description);
    // ruleid: js-html-from-user-text
    this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam);
    // ruleid: js-html-from-user-text
    this.link = this.sanitizer.bypassSecurityTrustUrl(row.url);
    // ruleid: js-html-from-user-text
    this.frame = this.sanitizer.bypassSecurityTrustResourceUrl(this.videoUrl);
    // ok: js-html-from-user-text
    this.badge = this.sanitizer.bypassSecurityTrustHtml('<b>new</b>');
    // ok: js-html-from-user-text
    this.body = this.sanitizer.bypassSecurityTrustHtml(DOMPurify.sanitize(row.body));
  }
}

// --- An escaping tag named html is not jQuery's .html(): opengrep reads html`...` as a call ---
// Imported by destructuring, which makes opengrep read html`...` as a method call on the module.
function stage(g) {
  const { html } = require('./lib/html');
  // ok: js-html-from-user-text
  return html`<div class="stage">
    ${media(g, { alt: g.link ? '' : 'Cover of ' + g.title })}
    <h2>${g.title}</h2>
  </div>`;
}

// jQuery on a stored selection or a $-named variable is still jQuery.
function jq($list, row) {
  // ruleid: js-html-from-user-text
  $list.html('<li>' + row.name + '</li>');
  // ruleid: js-html-from-user-text
  jQuery('#out').prepend('<b>' + row.comment + '</b>');
  // ruleid: js-html-from-user-text
  $('#who').html('<i>' + row.username + '</i>');
}

// --- A component or function that takes a record is not itself the HTML: only a template inside it can be ---
const Panel = ({ title, items }) => {
  const head = 'Panel';
  // ruleid: js-html-from-user-text
  const html = `<h2>${items[0].title}</h2>`;
  return html;
};

// --- XML is not a web page ---
function invoiceXml(inv) {
  // ok: js-html-from-user-text
  return `<?xml version="1.0" encoding="UTF-8"?>
<Invoice><Buyer>${inv.customer_name}</Buyer></Invoice>`;
}

// A record field in an arrow, but the template has no tag or the field is escaped.
function labels(rows) {
  // ok: js-html-from-user-text
  const plain = rows.map(({ title }) => `Title: ${title}`);
  // ok: js-html-from-user-text
  const safe = rows.map(({ title }) => `<li>${esc(title)}</li>`);
  return [plain, safe];
}

// --- A value handed to another function first: that function may escape it (a page() that escapes the title) ---
app.get('/book', (req, res) => {
  // ok: js-html-from-user-text
  res.send(page(res, `Booking ${settings.serviceName}`, '<h1>Book</h1>'));
});

// A list joined into markup by concatenation is still the markup itself.
function names(el, rows) {
  // ruleid: js-html-from-user-text
  el.innerHTML = rows.map(({ name }) => '<li>' + name).join('');
}
