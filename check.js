// Sealbridge Security: free email spoofing check.
// Runs entirely in the visitor's browser. Reads public DNS records through
// Cloudflare's DNS-over-HTTPS JSON API. Nothing is sent to Sealbridge.
'use strict';

(function () {
  var DOH = 'https://cloudflare-dns.com/dns-query';
  var CONTACT = 'ed.dupuy@gmail.com';
  var TLD_SWAPS = ['com', 'net', 'org', 'co', 'us', 'info', 'biz'];
  var MAX_LOOKALIKES = 60;

  var form = document.getElementById('check-form');
  var input = document.getElementById('domain');
  var button = document.getElementById('check-btn');
  var statusEl = document.getElementById('status');
  var results = document.getElementById('results');
  if (!form) return;

  // ---------- helpers ----------
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function normalize(raw) {
    var d = String(raw || '').trim().toLowerCase();
    if (d.indexOf('@') !== -1) d = d.slice(d.lastIndexOf('@') + 1);
    d = d.replace(/^[a-z]+:\/\//, '').split(/[\/?#:]/)[0].replace(/\.$/, '');
    if (d.indexOf('www.') === 0) d = d.slice(4);
    if (d.length > 253) return null;
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$/.test(d)) return null;
    return d;
  }

  function doh(name, type) {
    var url = DOH + '?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type);
    return fetch(url, { headers: { accept: 'application/dns-json' }, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' })
      .then(function (r) { if (!r.ok) throw new Error('DNS lookup failed (' + r.status + ')'); return r.json(); });
  }

  function txtValues(json, wantType) {
    var t = wantType || 16;
    return (json.Answer || []).filter(function (a) { return a.type === t; }).map(function (a) {
      // TXT data arrives as one or more quoted strings; join them.
      var parts = String(a.data).match(/"((?:[^"\\]|\\.)*)"/g);
      return parts ? parts.map(function (p) { return p.slice(1, -1).replace(/\\"/g, '"'); }).join('') : String(a.data);
    });
  }

  function tag(rec, name) {
    var m = new RegExp('(?:^|;)\\s*' + name + '\\s*=\\s*([^;]+)', 'i').exec(rec);
    return m ? m[1].trim() : null;
  }

  // ---------- checks ----------
  function checkMX(domain) {
    return doh(domain, 'MX').then(function (j) {
      var mx = (j.Answer || []).filter(function (a) { return a.type === 15; }).map(function (a) {
        var parts = String(a.data).split(/\s+/); return (parts[1] || parts[0]).replace(/\.$/, '');
      }).filter(Boolean);
      var provider = null;
      var all = mx.join(' ');
      if (/protection\.outlook\.com/.test(all)) provider = 'Microsoft 365';
      else if (/google\.com|googlemail\.com/.test(all)) provider = 'Google Workspace';
      return { exists: j.Status === 0, mx: mx, provider: provider, nxdomain: j.Status === 3 };
    });
  }

  function checkSPF(domain) {
    return doh(domain, 'TXT').then(function (j) {
      var spf = txtValues(j).filter(function (v) { return /^v=spf1(\s|$)/i.test(v); });
      if (spf.length === 0) return { level: 'bad', title: 'SPF: missing', detail: 'There is no list of services allowed to send your email, so receivers cannot tell real mail from fakes.' };
      if (spf.length > 1) return { level: 'bad', title: 'SPF: broken (' + spf.length + ' records)', detail: 'A domain may only publish one SPF record. With more than one, receivers treat SPF as failed.', record: spf.join('  |  ') };
      var rec = spf[0];
      var m = /([+?~-]?)all\b/i.exec(rec);
      if (!m) return { level: 'warn', title: 'SPF: no "all" rule', detail: 'Your SPF record never says what to do with unlisted senders.', record: rec };
      var q = m[1] || '+';
      if (q === '-') return { level: 'good', title: 'SPF: strict (-all)', detail: 'Mail from unlisted senders should be refused.', record: rec };
      if (q === '~') return { level: 'warn', title: 'SPF: soft (~all)', detail: 'Mail from unlisted senders is only marked as suspicious. That is common and acceptable when DMARC is set to quarantine or reject.', record: rec };
      return { level: 'bad', title: 'SPF: allows anyone (' + q + 'all)', detail: 'This setting lets any server on the internet send email as your domain.', record: rec };
    });
  }

  function checkDMARC(domain) {
    return doh('_dmarc.' + domain, 'TXT').then(function (j) {
      var recs = txtValues(j).filter(function (v) { return /^v=DMARC1/i.test(v); });
      if (recs.length === 0) return { level: 'bad', title: 'DMARC: missing', detail: 'Nothing tells other mail servers to block email pretending to be from your domain. This is the most important gap on this page.' };
      if (recs.length > 1) return { level: 'bad', title: 'DMARC: broken (' + recs.length + ' records)', detail: 'Only one DMARC record is allowed. With more than one, it is ignored.', record: recs.join('  |  ') };
      var rec = recs[0];
      var p = (tag(rec, 'p') || '').toLowerCase();
      var pct = parseInt(tag(rec, 'pct') || '100', 10);
      var res;
      if (p === 'reject') res = { level: 'good', title: 'DMARC: reject', detail: 'Fake email using your exact domain should be refused.' };
      else if (p === 'quarantine') res = { level: 'good', title: 'DMARC: quarantine', detail: 'Fake email using your exact domain should go to spam. "Reject" is stronger.' };
      else if (p === 'none') res = { level: 'bad', title: 'DMARC: monitoring only (p=none)', detail: 'The record exists but tells receivers to deliver fakes anyway. Many offices stop here by accident.' };
      else res = { level: 'bad', title: 'DMARC: no valid policy', detail: 'The record has no usable p= setting, so it does not block anything.' };
      if (res.level === 'good' && pct < 100) { res.level = 'warn'; res.detail += ' But pct=' + pct + ' means it only applies to ' + pct + '% of fake messages.'; }
      res.record = rec;
      return res;
    });
  }

  function checkDKIM(domain, provider, noMail) {
    if (noMail) return Promise.resolve({ level: 'info', title: 'DKIM: not needed', detail: 'This domain has no mail servers, so it doesn’t send or receive email and needs no signing keys. For a domain like this, a DMARC policy of "reject" and an SPF record ending in "-all" are what stop scammers from sending as it.' });
    var selectors = provider === 'Google Workspace' ? ['google'] : provider === 'Microsoft 365' ? ['selector1', 'selector2'] : ['selector1', 'selector2', 'google', 'k1', 'default'];
    return Promise.all(selectors.map(function (s) {
      var name = s + '._domainkey.' + domain;
      return Promise.all([doh(name, 'TXT'), doh(name, 'CNAME')]).then(function (rs) {
        var found = (rs[0].Answer || []).length > 0 || (rs[1].Answer || []).length > 0;
        return found ? s : null;
      }).catch(function () { return null; });
    })).then(function (found) {
      found = found.filter(Boolean);
      if (found.length) return { level: 'good', title: 'DKIM: signing key found', detail: 'Found key "' + found.join('", "') + '". Outgoing mail can be signed so receivers know it is really yours.' };
      if (provider) return { level: 'warn', title: 'DKIM: not found', detail: 'Your mail runs on ' + provider + ', but its standard signing keys are not published. Signing may be turned off.' };
      return { level: 'info', title: 'DKIM: couldn’t confirm', detail: 'Your email provider uses key names we can’t guess. A full check confirms this.' };
    });
  }

  // ---------- lookalikes ----------
  function lookalikes(domain) {
    var dot = domain.indexOf('.');
    var name = domain.slice(0, dot), tld = domain.slice(dot + 1);
    var out = {};
    function add(n, t) {
      if (!n || n.length < 2 || /^-|-$|--/.test(n) || !/^[a-z0-9-]+$/.test(n)) return;
      var d = n + '.' + (t || tld);
      if (d !== domain) out[d] = true;
    }
    var subs = [['m', 'rn'], ['rn', 'm'], ['w', 'vv'], ['l', 'i'], ['i', 'l'], ['o', '0'], ['0', 'o'], ['l', '1'], ['e', '3'], ['a', 'e'], ['e', 'a']];
    subs.forEach(function (s) {
      var idx = name.indexOf(s[0]);
      while (idx !== -1) { add(name.slice(0, idx) + s[1] + name.slice(idx + s[0].length)); idx = name.indexOf(s[0], idx + 1); }
    });
    for (var i = 0; i < name.length; i++) {
      add(name.slice(0, i) + name.slice(i + 1));                              // missing letter
      add(name.slice(0, i) + name[i] + name.slice(i));                        // doubled letter
      if (i < name.length - 1) add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2)); // swapped
    }
    TLD_SWAPS.forEach(function (t) { if (t !== tld) add(name, t); });
    ['-title', '-closing', '-escrow', '-realty', 'title', 'closing'].forEach(function (s) { add(name + s); });
    for (var j = 1; j < name.length; j++) add(name.slice(0, j) + '-' + name.slice(j));
    var list = Object.keys(out);
    // Put the most convincing ones first: TLD swaps and character tricks, then the rest.
    list.sort(function (a, b) { return score(b) - score(a); });
    function score(d) { var n = d.slice(0, d.indexOf('.')); return (n === name ? 3 : 0) + (/rn|vv|0|1/.test(n) && !/rn|vv|0|1/.test(name) ? 2 : 0) + (/-(title|closing|escrow|realty)$|title$|closing$/.test(n) ? 1 : 0); }
    return list.slice(0, MAX_LOOKALIKES);
  }

  function runPool(items, limit, fn, onProgress) {
    var i = 0, done = 0, out = new Array(items.length);
    return new Promise(function (resolve) {
      function next() {
        if (i >= items.length) { if (done === items.length) resolve(out); return; }
        var k = i++;
        fn(items[k]).then(function (r) { out[k] = r; }, function () { out[k] = null; }).then(function () {
          done++; if (onProgress) onProgress(done, items.length);
          if (done === items.length) resolve(out); else next();
        });
      }
      for (var n = 0; n < Math.min(limit, items.length); n++) next();
      if (!items.length) resolve(out);
    });
  }

  function probe(d) {
    return doh(d, 'NS').then(function (ns) {
      if (ns.Status !== 0 || !(ns.Answer || []).some(function (a) { return a.type === 2; })) return null;
      return doh(d, 'MX').then(function (mx) {
        var hasMx = (mx.Answer || []).some(function (a) { return a.type === 15 && !/^0\s+\.$/.test(String(a.data).trim()); });
        return { domain: d, mail: hasMx };
      });
    });
  }

  // ---------- rendering ----------
  function card(r) {
    var c = el('div', 'result result-' + r.level);
    var badge = { good: 'OK', warn: 'Weak', bad: 'Risk', info: 'Note' }[r.level];
    var head = el('div', 'result-head');
    head.appendChild(el('span', 'badge badge-' + r.level, badge));
    head.appendChild(el('h3', null, r.title));
    c.appendChild(head);
    c.appendChild(el('p', null, r.detail));
    if (r.record) c.appendChild(el('code', 'record', r.record));
    return c;
  }

  function render(domain, mx, checks, looks, tried) {
    results.textContent = '';
    var bad = checks.filter(function (c) { return c.level === 'bad'; }).length;
    var warn = checks.filter(function (c) { return c.level === 'warn'; }).length;
    var risky = looks.filter(function (l) { return l.mail; });
    var parked = looks.filter(function (l) { return !l.mail; });

    var verdict;
    if (bad > 0) verdict = { cls: 'bad', text: 'Scammers can likely send email that looks like it came from ' + domain + '.' };
    else if (warn > 0 || risky.length) verdict = { cls: 'warn', text: domain + ' has basic protection, with gaps worth fixing.' };
    else verdict = { cls: 'good', text: domain + ' blocks direct spoofing. Nice work.' };

    var sum = el('div', 'summary summary-' + verdict.cls);
    sum.appendChild(el('p', 'summary-text', verdict.text));
    var meta = el('p', 'fine', mx.provider ? 'Email provider: ' + mx.provider + '.' : (mx.mx.length ? 'Mail servers: ' + mx.mx.slice(0, 3).join(', ') + '.' : 'No mail servers found for this domain.'));
    sum.appendChild(meta);
    results.appendChild(sum);

    var h = el('h2', null, 'Your domain’s settings');
    results.appendChild(h);
    checks.forEach(function (c) { results.appendChild(card(c)); });

    results.appendChild(el('h2', null, 'Lookalike domains'));
    var lk = el('div', 'result result-' + (risky.length ? 'bad' : parked.length ? 'warn' : 'good'));
    var lh = el('div', 'result-head');
    lh.appendChild(el('span', 'badge badge-' + (risky.length ? 'bad' : parked.length ? 'warn' : 'good'), risky.length ? 'Risk' : parked.length ? 'Watch' : 'OK'));
    lh.appendChild(el('h3', null, risky.length + parked.length === 0 ? 'None of the ' + tried + ' common lookalikes we tried are registered' : (risky.length + parked.length) + ' of ' + tried + ' lookalikes we tried are registered'));
    lk.appendChild(lh);
    if (risky.length) {
      lk.appendChild(el('p', null, 'These can send and receive email, so they could be used to fake messages from your office:'));
      var ul = el('ul', 'lookalike-list');
      risky.forEach(function (l) { ul.appendChild(el('li', 'lookalike-mail', l.domain)); });
      lk.appendChild(ul);
    }
    if (parked.length) {
      lk.appendChild(el('p', null, (risky.length ? 'Also registered, but with no email set up (lower risk, worth watching):' : 'Registered, but with no email set up (lower risk, worth watching):')));
      var ul2 = el('ul', 'lookalike-list');
      parked.forEach(function (l) { ul2.appendChild(el('li', null, l.domain)); });
      lk.appendChild(ul2);
    }
    lk.appendChild(el('p', 'fine', 'Some are owned legitimately, possibly by you or a business with a similar name. We only see that a name exists, not who owns it.'));
    results.appendChild(lk);

    // Call to action
    var cta = el('div', 'check-cta');
    cta.appendChild(el('h2', null, bad || warn || risky.length ? 'Want a clear plan for these gaps before your next closing?' : 'Email settings are only part of the picture.'));
    cta.appendChild(el('p', null, 'A Security Check reviews sign-in security, hidden forwarding rules and lookalike domains, and gives you a written fix list your IT provider can work from. It starts with a 15-minute call, and any work is quoted after that call.'));
    var body = 'Hi Ed,\n\nI ran the free spoofing check on ' + domain + ' and would like to book a 15-minute call about the results.\n\nSummary: ' + verdict.text + '\n' +
      checks.map(function (c) { return '- ' + c.title; }).join('\n') +
      '\n- Lookalike domains registered: ' + (risky.length + parked.length) + ' of ' + tried + ' (' + risky.length + ' can send email)\n\nOffice name:\nNumber of people using email:\nBest time to call:\n';
    var a = el('a', 'btn', 'Book a 15-minute call');
    a.href = 'mailto:' + CONTACT + '?subject=' + encodeURIComponent('Spoofing check results for ' + domain) + '&body=' + encodeURIComponent(body);
    cta.appendChild(a);
    results.appendChild(cta);

    results.appendChild(el('p', 'fine', 'Checked ' + new Date().toLocaleString() + ' using public DNS. Results can change when settings change. This is an automated check, not a security assessment.'));

    results.hidden = false;
    results.querySelector('.summary').setAttribute('tabindex', '-1');
    results.querySelector('.summary').focus();
  }

  // ---------- run ----------
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var domain = normalize(input.value);
    results.hidden = true;
    if (!domain) { statusEl.textContent = 'Please enter a domain like yourbrokerage.com, or an email address.'; input.focus(); return; }
    input.value = domain;
    button.disabled = true;
    statusEl.textContent = 'Checking ' + domain + '…';

    checkMX(domain).then(function (mx) {
      if (mx.nxdomain) throw new Error(domain + ' doesn’t exist in DNS. Check the spelling and try again.');
      statusEl.textContent = 'Checking ' + domain + '’s anti-spoofing settings…';
      return Promise.all([checkDMARC(domain), checkSPF(domain), checkDKIM(domain, mx.provider, mx.mx.length === 0)]).then(function (checks) {
        var list = lookalikes(domain);
        return runPool(list, 6, probe, function (d, n) { statusEl.textContent = 'Looking for lookalike domains… ' + d + ' of ' + n; })
          .then(function (looks) { return { mx: mx, checks: checks, looks: looks, tried: list.length }; });
      });
    }).then(function (r) {
      render(domain, r.mx, r.checks, r.looks.filter(Boolean), r.tried);
      statusEl.textContent = 'Done. Results for ' + domain + ' are below.';
    }).catch(function (err) {
      statusEl.textContent = (err && err.message ? err.message : 'Something went wrong.') + ' If it keeps happening, email ' + CONTACT + ' and we’ll run it for you.';
    }).then(function () { button.disabled = false; });
  });
})();
