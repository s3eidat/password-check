/* Password Check — pattern-aware strength estimate (zxcvbn-style). The password stays in memory only: never stored, logged or sent. */
(function () {
  "use strict";
  var $ = S3.$;
  var COMMON = new Map();
  (window.PC_COMMON || []).forEach(function (w, i) { if (!COMMON.has(w)) COMMON.set(w, i + 1); });
  var WORDS = new Set(window.PC_WORDS || []);
  var WORD_GUESSES = 20000; // a real attacker's dictionary is far bigger than ours, so a known word costs about its rank there
  var MAX_LEN = 256;

  // ---------- small maths ----------
  function log2fact(n) { var s = 0; for (var i = 2; i <= n; i++) s += Math.log2(i); return s; }
  function nCk(n, k) { if (k > n) return 0; var r = 1; for (var i = 1; i <= k; i++) r = r * (n - k + i) / i; return r; }
  function log2add(a, b) { var hi = Math.max(a, b), lo = Math.min(a, b); return hi + Math.log2(1 + Math.pow(2, lo - hi)); }

  function charClass(c) {
    if (/[a-z]/.test(c)) return "lower";
    if (/[A-Z]/.test(c)) return "upper";
    if (/[0-9]/.test(c)) return "digit";
    if (/[\x20-\x7e]/.test(c)) return "symbol";
    return "other";
  }
  var CARD = { lower: 26, upper: 26, digit: 10, symbol: 33, other: 100 };
  function cardinality(chars) {
    var seen = {}, c = 0;
    chars.forEach(function (ch) { var k = charClass(ch); if (!seen[k]) { seen[k] = 1; c += CARD[k]; } });
    return c;
  }

  // ---------- matchers: each returns [{i, j, type, token, log2: log2(guesses), note}] ----------
  var LEET = { "4": ["a"], "@": ["a"], "8": ["b"], "(": ["c"], "{": ["c"], "3": ["e"], "6": ["g"], "9": ["g"], "1": ["i", "l"], "!": ["i"], "|": ["i", "l"], "0": ["o"], "$": ["s"], "5": ["s"], "7": ["t"], "+": ["t"], "2": ["z"], "%": ["x"] };

  function upperVariations(token) {
    var U = 0, L = 0;
    Array.from(token).forEach(function (c) { if (/[A-Z]/.test(c)) U++; else if (/[a-z]/.test(c)) L++; });
    if (!U) return 1;
    if (!L || (U === 1 && (/^[A-Z]/.test(token) || /[A-Z]$/.test(token)))) return 2;
    var v = 0; for (var i = 1; i <= Math.min(U, L); i++) v += nCk(U + L, i);
    return v;
  }
  function leetVariations(token, subs) {
    var v = 1;
    Object.keys(subs).forEach(function (leetChar) {
      var S = 0, U = 0, plain = subs[leetChar];
      Array.from(token.toLowerCase()).forEach(function (c) { if (c === leetChar) S++; else if (c === plain) U++; });
      var p = 1;
      if (U) { p = 0; for (var i = 1; i <= Math.min(S, U); i++) p += nCk(S + U, i); }
      v *= Math.max(2, p);
    });
    return v;
  }
  // All plain-letter readings of a l33t token (capped so pathological input can't explode).
  function unleet(lower) {
    var outs = [{ s: "", subs: {} }];
    for (var k = 0; k < lower.length; k++) {
      var c = lower[k], opts = LEET[c], next = [];
      outs.forEach(function (o) {
        next.push({ s: o.s + c, subs: o.subs });
        if (opts) opts.forEach(function (p) { var s2 = Object.assign({}, o.subs); s2[c] = p; next.push({ s: o.s + p, subs: s2 }); });
      });
      outs = next.slice(0, 64);
    }
    return outs.filter(function (o) { return Object.keys(o.subs).length; });
  }
  function dictLookup(lower) {
    if (COMMON.has(lower)) return { rank: COMMON.get(lower), kind: "common" };
    if (WORDS.has(lower)) return { rank: WORD_GUESSES, kind: "word" };
    return null;
  }
  function dictionaryMatches(chars) {
    var out = [], n = chars.length;
    for (var i = 0; i < n; i++) for (var j = i + 2; j < Math.min(n, i + 24); j++) {
      var token = chars.slice(i, j + 1).join(""), lower = token.toLowerCase();
      var hit = dictLookup(lower), uv = upperVariations(token);
      if (hit) out.push({ i: i, j: j, type: hit.kind, token: token, log2: Math.log2(hit.rank * uv), rank: hit.rank, caps: uv > 1 });
      var rev = Array.from(lower).reverse().join("");
      if (rev !== lower) { var rh = dictLookup(rev); if (rh) out.push({ i: i, j: j, type: rh.kind, token: token, log2: Math.log2(rh.rank * uv * 2), rank: rh.rank, reversed: true, caps: uv > 1 }); }
      if (/[0-9@!$|(){}+%]/.test(lower)) unleet(lower).forEach(function (u) {
        var lh = dictLookup(u.s);
        if (lh) out.push({ i: i, j: j, type: lh.kind, token: token, log2: Math.log2(lh.rank * uv * leetVariations(token, u.subs)), rank: lh.rank, leet: u.s, caps: uv > 1 });
      });
    }
    return out;
  }

  function sequenceMatches(chars) {
    var out = [], n = chars.length, i = 0;
    while (i < n - 2) {
      var d = chars[i + 1].charCodeAt(0) - chars[i].charCodeAt(0), j = i + 1;
      if ((d === 1 || d === -1) && charClass(chars[i]) === charClass(chars[i + 1]) && /lower|upper|digit/.test(charClass(chars[i]))) {
        while (j + 1 < n && chars[j + 1].charCodeAt(0) - chars[j].charCodeAt(0) === d && charClass(chars[j + 1]) === charClass(chars[i])) j++;
      }
      if (j - i >= 2) {
        var first = chars[i], base = "aAzZ019".indexOf(first) >= 0 ? 4 : charClass(first) === "digit" ? 10 : 26;
        out.push({ i: i, j: j, type: "sequence", token: chars.slice(i, j + 1).join(""), log2: Math.log2(base * (j - i + 1) * (d < 0 ? 2 : 1)) });
        i = j;
      } else i++;
    }
    return out;
  }

  // Keyboard graph: QWERTY rows (slanted) + numeric keypad. Shifted characters map to the same key.
  var ROWS = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"];
  var SROWS = ["~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?"];
  var KEYS = {};
  ROWS.forEach(function (r, ri) { Array.from(r).forEach(function (c, ci) { KEYS[c] = { b: "q", r: ri, c: ci, s: 0 }; KEYS[SROWS[ri][ci]] = { b: "q", r: ri, c: ci, s: 1 }; }); });
  var PAD = ["789", "456", "123", "0.."];
  var PADKEYS = {};
  PAD.forEach(function (r, ri) { Array.from(r).forEach(function (c, ci) { if (c !== "." || ri !== 3 || ci === 2) PADKEYS[c] = { b: "k", r: ri, c: ci, s: 0 }; }); });
  function adjacentQ(a, b) {
    var dr = b.r - a.r, dc = b.c - a.c;
    if (dr === 0) return Math.abs(dc) === 1;
    if (dr === -1) return dc === 0 || dc === 1;
    if (dr === 1) return dc === 0 || dc === -1;
    return false;
  }
  function adjacentK(a, b) { return Math.max(Math.abs(a.r - b.r), Math.abs(a.c - b.c)) === 1; }
  function walks(chars, map, adj, starts, degree) {
    var out = [], n = chars.length, i = 0;
    while (i < n - 2) {
      var j = i, turns = 0, dir = null, shifted = map[chars[i]] ? map[chars[i]].s : 0;
      while (j + 1 < n && map[chars[j]] && map[chars[j + 1]] && adj(map[chars[j]], map[chars[j + 1]])) {
        var nd = (map[chars[j + 1]].r - map[chars[j]].r) + "," + (map[chars[j + 1]].c - map[chars[j]].c);
        if (nd !== dir) { turns++; dir = nd; }
        shifted += map[chars[j + 1]].s; j++;
      }
      var len = j - i + 1;
      if (len >= 3) {
        var g = Math.log2(starts) + Math.log2(len) + (turns - 1) * Math.log2(degree);
        if (shifted && shifted < len) g += Math.log2(Math.min(len, 8) * 2);
        else if (shifted) g += 1;
        out.push({ i: i, j: j, type: "keyboard", token: chars.slice(i, j + 1).join(""), log2: g, turns: turns });
        i = j;
      } else i++;
    }
    return out;
  }
  function spatialMatches(chars) {
    return walks(chars, KEYS, adjacentQ, 47, 4.6).concat(walks(chars, PADKEYS, adjacentK, 11, 5));
  }

  function repeatMatches(chars, depth) {
    var out = [], s = chars.join(""), pos = 0;
    while (pos < s.length) {
      var rest = s.slice(pos), g = /(.+)\1+/.exec(rest);
      if (!g) break;
      var l = /(.+?)\1+/.exec(rest), m = g[0].length > l[0].length ? g : l; // same start; prefer the longer run, else the smaller unit
      var base = m[1], token = m[0], reps = token.length / base.length;
      var i = Array.from(s.slice(0, pos + m.index)).length, len = Array.from(token).length;
      var baseG = depth > 2 ? Array.from(base).length * Math.log2(cardinality(Array.from(base))) : estimate(base, depth + 1).log2;
      out.push({ i: i, j: i + len - 1, type: "repeat", token: token, base: base, log2: baseG + Math.log2(reps) });
      pos += m.index + token.length;
    }
    return out;
  }

  var NOW_YEAR = 2026;
  function yearSpace(y) { return Math.max(Math.abs(y - NOW_YEAR), 20); }
  function validDate(d, mo, y) { return mo >= 1 && mo <= 12 && d >= 1 && d <= 31 && y >= 1900 && y <= 2099; }
  function fullYear(s) { var y = +s; return s.length === 2 ? (y > 50 ? 1900 + y : 2000 + y) : y; }
  function dateMatches(chars) {
    var out = [], n = chars.length;
    for (var i = 0; i < n; i++) for (var j = i + 3; j < Math.min(n, i + 10); j++) {
      var t = chars.slice(i, j + 1).join("");
      if (/^\d{4}$/.test(t) && +t >= 1900 && +t <= 2099) { out.push({ i: i, j: j, type: "year", token: t, log2: Math.log2(yearSpace(+t)) }); }
      var parts = null, sep = false, m = /^(\d{1,4})([\/\-. _])(\d{1,2})\2(\d{1,4})$/.exec(t);
      if (m) { parts = [[m[1], m[3], m[4]]]; sep = true; }
      else if (/^\d{4,8}$/.test(t)) {
        parts = [];
        for (var a = 1; a <= 4; a++) for (var b = 1; b <= 2; b++) { var c = t.length - a - b; if (c >= 1 && c <= 4) parts.push([t.slice(0, a), t.slice(a, a + b), t.slice(a + b)]); }
      }
      if (!parts) continue;
      var best = null;
      parts.forEach(function (p) {
        [[0, 1, 2], [1, 0, 2], [2, 1, 0]].forEach(function (o) { // d-m-y, m-d-y, y-m-d
          var ys = p[o[2]], ds = p[o[0]], ms = p[o[1]];
          if (!(ys.length === 2 || ys.length === 4) || ds.length > 2 || ms.length > 2) return;
          var y = fullYear(ys);
          if (validDate(+ds, +ms, y)) { var g = Math.log2(365 * yearSpace(y) * (sep ? 4 : 1)); if (best === null || g < best) best = g; }
        });
      });
      if (best !== null) out.push({ i: i, j: j, type: "date", token: t, log2: best });
    }
    return out;
  }

  // ---------- the search: cheapest cover of the whole password ----------
  function estimate(pw, depth) {
    depth = depth || 0;
    var chars = Array.from(pw).slice(0, MAX_LEN), n = chars.length;
    if (!n) return { log2: 0, seq: [], chars: chars };
    var matches = dictionaryMatches(chars).concat(sequenceMatches(chars), spatialMatches(chars), repeatMatches(chars, depth), dateMatches(chars));
    var perChar = Math.log2(cardinality(chars)); // an attacker's mask covers every character type the password uses
    for (var i = 0; i < n; i++) for (var j = i; j < n; j++) {
      matches.push({ i: i, j: j, type: "bruteforce", token: chars.slice(i, j + 1).join(""), log2: Math.max((j - i + 1) * perChar, 1) });
    }
    var byEnd = []; for (var e = 0; e < n; e++) byEnd.push([]);
    matches.forEach(function (m) { byEnd[m.j].push(m); });
    // best[j][k] = min sum(log2 guesses) covering chars[0..j] with k matches
    var best = [], back = [];
    for (var jj = 0; jj < n; jj++) { best.push({}); back.push({}); }
    for (var j2 = 0; j2 < n; j2++) byEnd[j2].forEach(function (m) {
      if (m.i === 0) { if (!(1 in best[j2]) || m.log2 < best[j2][1]) { best[j2][1] = m.log2; back[j2][1] = m; } return; }
      var prev = best[m.i - 1];
      for (var k in prev) {
        var k1 = +k + 1, v = prev[k] + m.log2;
        if (!(k1 in best[j2]) || v < best[j2][k1]) { best[j2][k1] = v; back[j2][k1] = m; }
      }
    });
    var bestTotal = Infinity, bestK = 1;
    for (var kk in best[n - 1]) {
      var K = +kk, tot = log2add(log2fact(K) + best[n - 1][kk], (K - 1) * Math.log2(10000));
      if (tot < bestTotal) { bestTotal = tot; bestK = K; }
    }
    var seq = [], at = n - 1, kNow = bestK;
    while (at >= 0) { var mm = back[at][kNow]; seq.unshift(mm); at = mm.i - 1; kNow--; }
    // Anything beyond MAX_LEN is counted as random characters.
    var extra = Array.from(pw).slice(MAX_LEN);
    if (extra.length) bestTotal += extra.length * Math.log2(cardinality(extra));
    return { log2: Math.max(bestTotal, 0), seq: seq, chars: chars };
  }

  // ---------- presentation ----------
  var RATES = [100 / 3600, 10, 1e4, 1e10];
  function fmtTime(sec) {
    if (sec < 1) return "instant";
    var u = [["century", 3155760000, "centuries"], ["year", 31557600], ["month", 2629800], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    if (sec / 3155760000 >= 1e4) {
      var y = sec / 31557600, big = [["trillion", 1e12], ["billion", 1e9], ["million", 1e6], ["thousand", 1e3]];
      if (y >= 1e15) return "10^" + Math.floor(Math.log10(y)) + " years";
      for (var b = 0; b < big.length; b++) if (y >= big[b][1]) return Math.round(y / big[b][1]).toLocaleString() + " " + big[b][0] + " years";
    }
    for (var i = 0; i < u.length; i++) if (sec >= u[i][1]) {
      var n = Math.round(sec / u[i][1]);
      return n.toLocaleString() + " " + (n === 1 ? u[i][0] : u[i][2] || u[i][0] + "s");
    }
    return "";
  }
  var SCORES = [["Very weak", "bad"], ["Weak", "bad"], ["Fair", "warn"], ["Strong", "ok"], ["Very strong", "ok"]];
  function score(bits) { return bits < 20 ? 0 : bits < 35 ? 1 : bits < 50 ? 2 : bits < 65 ? 3 : 4; }

  function tipsFor(r, pw) {
    var t = [], types = {}, s = score(r.log2), len = r.chars.length;
    r.seq.forEach(function (m) { types[m.type] = m; });
    if (r.seq.length === 1 && types.common) t.push("This is one of the most common passwords (about #" + types.common.rank + " on lists attackers try first). Never use it.");
    else if (types.common) t.push("It contains a very common password. Attackers try those, and variations of them, first.");
    if (r.seq.length === 1 && types.word) t.push("A single dictionary word is guessed in seconds, whatever you do to it.");
    else if (types.word && s < 3) t.push("Common words are guessed early. A few unrelated random words are fine, one or two are not.");
    if (r.seq.some(function (m) { return m.leet; })) t.push("Swaps like @ for a or 0 for o are the first variations attackers try. They add almost nothing.");
    if (r.seq.some(function (m) { return m.reversed; })) t.push("Reversed words are no harder to guess than normal ones.");
    if (r.seq.some(function (m) { return m.caps && /^[A-Z][^A-Z]*$/.test(m.token); })) t.push("Capitalizing only the first letter barely helps.");
    if (r.seq.some(function (m) { return m.caps && m.token.length > 2 && m.token === m.token.toUpperCase(); })) t.push("ALL CAPS is about as easy to guess as all lowercase.");
    if (types.keyboard) t.push("Keyboard patterns like qwerty, asdf or 1qaz2wsx are in every cracking list.");
    if (types.sequence) t.push("Sequences like abc or 6789 are easy to guess.");
    if (types.repeat) t.push("Repeats like aaa or abcabc add very little over the part being repeated.");
    if (types.year || types.date) t.push("Years and dates are easy to guess, especially birthdays and anniversaries.");
    if (/[!1.?]$/.test(pw) && r.seq.length > 1 && s < 4) t.push("Ending with ! or 1 is the most common trick, so attackers expect it.");
    if (len < 12) t.push("Use at least 12–16 characters. Length beats complexity.");
    if (s < 3) t.push("Try a passphrase of 5–6 random words (a generator picks better than people do).");
    if (s >= 4) t.push("Excellent. Keep it unique to one account so a leak elsewhere can't unlock it.");
    else if (s === 3) t.push("Good. Make it a little longer if this protects email, banking or a password manager.");
    t.push("Use a different password for every site. A password manager makes that painless.");
    return t;
  }

  var LABEL = { common: "common password", word: "dictionary word", keyboard: "keyboard pattern", sequence: "sequence", repeat: "repeat", year: "year", date: "date", bruteforce: "random characters" };
  var input = $("#pw"), shown = false;
  function mask(s) { return shown ? s : "•".repeat(Array.from(s).length); }

  function render() {
    var pw = input.value, meter = S3.$$(".pc-meter i");
    if (!pw) {
      $("#score").className = "chip"; $("#score").textContent = "Type a password"; $("#bits").textContent = "";
      meter.forEach(function (i) { i.className = ""; });
      S3.$$("#times td:last-child").forEach(function (td) { td.textContent = "—"; });
      $("#parts").innerHTML = '<span class="faint">Your password split into the cheapest-to-guess pieces will show here.</span>';
      $("#tips").innerHTML = '<li class="muted">Start typing to get advice for your password.</li>';
      $("#stats").innerHTML = "";
      return;
    }
    var r = estimate(pw), s = score(r.log2);
    $("#score").className = "chip " + SCORES[s][1]; $("#score").textContent = SCORES[s][0];
    $("#bits").textContent = "≈ " + r.log2.toFixed(1) + " bits · about 10^" + Math.round(r.log2 * Math.log10(2)) + " guesses";
    meter.forEach(function (el, i) { el.className = i <= s ? "pc-" + SCORES[s][1] : ""; });
    S3.$$("#times td:last-child").forEach(function (td, i) { td.textContent = fmtTime(Math.pow(2, r.log2) / RATES[i]); });
    var parts = $("#parts"); parts.innerHTML = "";
    r.seq.forEach(function (m) {
      var note = LABEL[m.type] + (m.type === "common" ? " #" + m.rank : "") + (m.leet ? " (l33t)" : "") + (m.reversed ? " (reversed)" : "") + (m.type === "repeat" ? " ×" + Math.round(Array.from(m.token).length / Array.from(m.base).length) : "");
      parts.appendChild(S3.h("div", { "class": "pc-part pc-" + m.type }, [
        S3.h("span", { "class": "mono pc-tok", dir: "auto" }, [mask(m.token)]),
        S3.h("span", { "class": "pc-what" }, [note]),
        S3.h("span", { "class": "faint" }, ["≈ " + m.log2.toFixed(1) + " bits"])
      ]));
    });
    var ul = $("#tips"); ul.innerHTML = "";
    tipsFor(r, pw).forEach(function (t) { ul.appendChild(S3.h("li", null, [t])); });
    var classes = {}; r.chars.forEach(function (c) { classes[charClass(c)] = 1; });
    $("#stats").innerHTML = "";
    [[r.chars.length, "characters"], [Object.keys(classes).length, "character types"], [r.seq.length, "pieces found"]].forEach(function (x) {
      $("#stats").appendChild(S3.h("div", { "class": "stat" }, [S3.h("b", { text: String(x[0]) }), S3.h("span", { text: x[1] })]));
    });
  }

  input.addEventListener("input", S3.debounce(render, 120));
  $("#show").addEventListener("click", function () {
    shown = !shown; input.type = shown ? "text" : "password";
    this.setAttribute("aria-pressed", String(shown)); this.firstChild.textContent = shown ? "Hide" : "Show";
    render();
  });
  $("#clear").addEventListener("click", function () { input.value = ""; render(); input.focus(); });
  // Don't leave the password sitting in a background tab's form state.
  window.addEventListener("pagehide", function () { input.value = ""; });
  render();

  window.S3_DEMO = function () { input.value = "Summer2024!"; if (!shown) $("#show").click(); else render(); };

  window.S3_SELFTEST = function () {
    var ok = true, fail = function (w) { ok = false; console.error("selftest: " + w); };
    function bits(p) { return estimate(p).log2; }
    function types(p) { return estimate(p).seq.map(function (m) { return m.type; }); }
    if (!(bits("password") < 5) || types("password")[0] !== "common") fail("password");
    if (!(bits("123456") < 3)) fail("123456");
    var lp = estimate("P4ssw0rd"); if (!(lp.log2 < 15) || !lp.seq[0].leet) fail("l33t " + lp.log2);
    if (!(bits("drowssap") < 10)) fail("reversed");
    if (!(bits("abcdefghij") < 10) || types("abcdefghij")[0] !== "sequence") fail("sequence");
    if (!(bits("aaaaaaaaaaaa") < 10) || types("aaaaaaaaaaaa")[0] !== "repeat") fail("repeat " + bits("aaaaaaaaaaaa") + " " + types("aaaaaaaaaaaa"));
    var sp = spatialMatches(Array.from("wsxedc"));
    if (sp.length !== 2 || sp[0].j !== 2 || sp[1].i !== 3) fail("keyboard walk");
    if (!(bits("wsxedcrfv") < 30)) fail("keyboard bits " + bits("wsxedcrfv"));
    if (!(bits("19/07/1994") < 25) || types("19/07/1994")[0] !== "date") fail("date");
    if (types("1994")[0] !== "year") fail("year");
    if (!(bits("Summer2024!") < 40)) fail("summer");
    if (!(bits("kT9#vQ2$xL7!mR4@") > 80)) fail("random16 " + bits("kT9#vQ2$xL7!mR4@"));
    if (!(bits("correct horse battery staple") > 50)) fail("passphrase");
    if (bits("") !== 0) fail("empty");
    if (Math.abs(bits("zq") - Math.log2(26 * 26 + 1)) > 1e-9) fail("bruteforce maths"); // 26^2 guesses, +1 from the sequence term
    if (fmtTime(59) !== "59 seconds" || fmtTime(3600) !== "1 hour") fail("fmtTime");
    if (score(19.9) !== 0 || score(70) !== 4) fail("score");
    return ok;
  };
})();
