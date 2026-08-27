/* Password Forge - all generation happens locally, nothing leaves the page. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  /* ---------------- cryptographic randomness ---------------- */

  // Uniform integer in [0, max) with rejection sampling, so no value is favoured.
  function randInt(max) {
    if (max <= 0) return 0;
    var limit = Math.floor(4294967296 / max) * max;
    var buf = new Uint32Array(1);
    var v;
    do {
      crypto.getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }

  function pick(arr) { return arr[randInt(arr.length)]; }

  /* ---------------- character sets ---------------- */

  var SETS = {
    lower: "abcdefghijklmnopqrstuvwxyz",
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{};:,.?/"
  };
  var AMBIGUOUS = "Il1O0oB8S5Z2G6|`'\"";

  function activeSets() {
    var out = [];
    if ($("optLower").checked) out.push("lower");
    if ($("optUpper").checked) out.push("upper");
    if ($("optDigits").checked) out.push("digits");
    if ($("optSymbols").checked) out.push("symbols");
    return out;
  }

  function poolFor(names) {
    var strip = $("optNoAmbiguous").checked;
    return names.map(function (n) {
      var s = SETS[n];
      if (strip) s = s.split("").filter(function (c) { return AMBIGUOUS.indexOf(c) === -1; }).join("");
      return s;
    });
  }

  function makeCharPassword(length, names) {
    var parts = poolFor(names).filter(function (s) { return s.length > 0; });
    if (!parts.length) return "";
    var all = parts.join("");
    var chars = [];
    var i;
    // One character from each requested set first, so every set really appears.
    for (i = 0; i < parts.length && i < length; i++) chars.push(parts[i][randInt(parts[i].length)]);
    for (i = chars.length; i < length; i++) chars.push(all[randInt(all.length)]);
    // Fisher-Yates shuffle with the same uniform source.
    for (i = chars.length - 1; i > 0; i--) {
      var j = randInt(i + 1);
      var t = chars[i]; chars[i] = chars[j]; chars[j] = t;
    }
    return chars.join("");
  }

  function currentSeparator() {
    var el = document.querySelector('input[name="sep"]:checked');
    return el ? el.value : " ";
  }

  function makeWordPassword(count, addDigits, caps, sep) {
    var out = [];
    for (var i = 0; i < count; i++) {
      var w = pick(WORDS);
      if (caps) w = w.charAt(0).toUpperCase() + w.slice(1);
      if (addDigits) w += String(randInt(10));
      out.push(w);
    }
    return out.join(sep);
  }

  /* ---------------- entropy and crack time ---------------- */

  var LOG10_2 = Math.log10(2);
  var SEC_PER_YEAR = 31557600;
  var SUP = { "0": "⁰", "1": "¹", "2": "²", "3": "³", "4": "⁴",
              "5": "⁵", "6": "⁶", "7": "⁷", "8": "⁸", "9": "⁹" };

  function superscript(n) {
    return String(n).split("").map(function (c) { return SUP[c] || c; }).join("");
  }

  // Render a number given only its base-10 logarithm.
  function fromLog10(log10, unit) {
    if (log10 < 6) {
      var v = Math.pow(10, log10);
      return v.toLocaleString(undefined, { maximumFractionDigits: v < 10 ? 1 : 0 }) + (unit ? " " + unit : "");
    }
    var scales = [
      [6, "million"], [9, "billion"], [12, "trillion"], [15, "quadrillion"], [18, "quintillion"]
    ];
    for (var i = scales.length - 1; i >= 0; i--) {
      if (log10 >= scales[i][0] && log10 < scales[i][0] + 3) {
        var m = Math.pow(10, log10 - scales[i][0]);
        return m.toFixed(m < 10 ? 1 : 0) + " " + scales[i][1] + (unit ? " " + unit : "");
      }
    }
    var e = Math.floor(log10);
    var mant = Math.pow(10, log10 - e);
    return mant.toFixed(1) + " × 10" + superscript(e) + (unit ? " " + unit : "");
  }

  function crackTimeText(bits, rate) {
    // Average case: half the search space.
    var log10sec = (bits - 1) * LOG10_2 - Math.log10(rate);
    if (log10sec < -1) return "instantly";
    var sec = log10sec < 12 ? Math.pow(10, log10sec) : Infinity;
    if (sec < 1) return "under a second";
    if (sec < 60) return fromLog10(log10sec, sec < 1.5 ? "second" : "seconds");
    if (sec < 3600) return fromLog10(log10sec - Math.log10(60), "minutes");
    if (sec < 86400) return fromLog10(log10sec - Math.log10(3600), "hours");
    if (sec < SEC_PER_YEAR) return fromLog10(log10sec - Math.log10(86400), "days");
    var log10years = log10sec - Math.log10(SEC_PER_YEAR);
    if (log10years > 30) return "longer than the universe has existed, many times over";
    return fromLog10(log10years, "years");
  }

  function verdictFor(bits) {
    if (bits < 36) return ["Very weak", "var(--bad)", 0.10];
    if (bits < 55) return ["Weak", "var(--bad)", 0.28];
    if (bits < 70) return ["Fair", "var(--warn)", 0.46];
    if (bits < 90) return ["Strong", "var(--ok)", 0.66];
    if (bits < 120) return ["Very strong", "var(--ok)", 0.85];
    return ["Excellent", "var(--ok)", 1];
  }

  /* ---------------- rendering ---------------- */

  function renderPassword(pw) {
    var out = $("pwInner");
    out.textContent = "";
    if (!pw) { out.textContent = "\u00a0"; return; }
    var frag = document.createDocumentFragment();
    for (var i = 0; i < pw.length; i++) {
      var c = pw[i];
      var cls = /[0-9]/.test(c) ? "d" : (/[a-zA-Z ]/.test(c) ? "" : "s");
      if (cls) {
        var s = document.createElement("span");
        s.className = cls;
        s.textContent = c;
        frag.appendChild(s);
      } else {
        frag.appendChild(document.createTextNode(c));
      }
    }
    out.appendChild(frag);
  }

  function updateMeter(bits, detail) {
    var v = verdictFor(bits);
    $("verdict").textContent = v[0];
    $("verdict").style.color = v[1];
    $("meterFill").style.width = (v[2] * 100).toFixed(1) + "%";
    $("meterFill").style.background = v[1];
    $("bits").textContent = bits.toFixed(1);
    $("combos").textContent = fromLog10(bits * LOG10_2, "");
    $("crackTime").textContent = crackTimeText(bits, parseFloat($("attacker").value));
    $("entropyNote").textContent = detail;
  }

  /* ---------------- the main update ---------------- */

  var currentPassword = "";

  function generate() {
    var mode = document.querySelector('input[name="mode"]:checked').value;
    var bits = 0, detail = "";

    if (mode === "chars") {
      var names = activeSets();
      var warn = $("charWarn");
      if (!names.length) {
        warn.hidden = false;
        currentPassword = "";
        renderPassword("");
        updateMeter(0, "Nothing to draw from yet.");
        return;
      }
      warn.hidden = true;
      var len = parseInt($("charLen").value, 10);
      var poolSize = poolFor(names).join("").length;
      currentPassword = makeCharPassword(len, names);
      bits = len * Math.log2(poolSize);
      detail = len + " characters drawn from a pool of " + poolSize +
               ", which is " + Math.log2(poolSize).toFixed(1) + " bits per character.";
    } else {
      var count = parseInt($("wordCount").value, 10);
      var addDigits = $("wOptDigits").checked;
      var caps = $("wOptCaps").checked;
      var sep = currentSeparator();
      currentPassword = makeWordPassword(count, addDigits, caps, sep);
      var perWord = Math.log2(WORDS.length);
      bits = count * perWord + (addDigits ? count * Math.log2(10) : 0);
      detail = count + " words drawn from a list of " + WORDS.length.toLocaleString() +
               " (" + perWord.toFixed(1) + " bits each)" +
               (addDigits ? ", plus one random digit per word (3.3 bits each)" : "") +
               ". The spacing character and the capitalisation are the same every time, so they add no entropy: length is what protects you.";
      $("wordNote").textContent = "Attackers know which word lists generators use. The strength above already assumes they do.";
    }

    renderPassword(currentPassword);
    updateMeter(bits, detail);
    resetCopyLabel();
  }

  /* ---------------- copy ---------------- */

  var copyTimer = null;

  function resetCopyLabel() {
    if (copyTimer) { clearTimeout(copyTimer); copyTimer = null; }
    $("copyLabel").textContent = "Copy password";
    $("copyBtn").classList.remove("copied");
  }

  function flashCopied(text) {
    $("copyLabel").textContent = text;
    $("copyBtn").classList.add("copied");
    if (copyTimer) clearTimeout(copyTimer);
    copyTimer = setTimeout(resetCopyLabel, 2000);
  }

  function copyPassword() {
    if (!currentPassword) return;
    var done = function () { flashCopied("Copied"); };
    var fail = function () {
      try {
        var ta = document.createElement("textarea");
        ta.value = currentPassword;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        done();
      } catch (e) {
        flashCopied("Press Ctrl+C to copy");
      }
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(currentPassword).then(done, fail);
    } else {
      fail();
    }
  }

  /* ---------------- segmented switch thumbs ---------------- */

  function moveThumb(group) {
    var inputs = group.querySelectorAll('input[type="radio"]');
    var thumb = group.querySelector(".segment-thumb");
    if (!thumb) return;
    for (var i = 0; i < inputs.length; i++) {
      if (inputs[i].checked) {
        thumb.style.transform = "translateX(calc((100% + 4px) * " + i + "))";
        return;
      }
    }
  }

  function wireSegments() {
    var groups = document.querySelectorAll(".segment");
    Array.prototype.forEach.call(groups, function (g) {
      moveThumb(g);
      g.addEventListener("change", function () { moveThumb(g); });
    });
  }

  /* ---------------- theme ---------------- */

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $("themeToggle").checked = theme === "dark";
    try { localStorage.setItem("pf-theme", theme); } catch (e) {}
  }

  /* ---------------- wiring ---------------- */

  function switchMode() {
    var mode = document.querySelector('input[name="mode"]:checked').value;
    $("panelChars").hidden = mode !== "chars";
    $("panelWords").hidden = mode !== "words";
    generate();
  }

  function init() {
    // Theme: light unless the visitor chose dark before (the inline head script
    // already applied it, this only syncs the switch).
    var stored = null;
    try { stored = localStorage.getItem("pf-theme"); } catch (e) {}
    $("themeToggle").checked = stored === "dark";
    $("themeToggle").addEventListener("change", function () {
      applyTheme(this.checked ? "dark" : "light");
    });

    wireSegments();

    $("charLen").addEventListener("input", function () {
      $("charLenValue").textContent = this.value;
      generate();
    });
    $("wordCount").addEventListener("input", function () {
      $("wordCountValue").textContent = this.value;
      generate();
    });

    ["optLower", "optUpper", "optDigits", "optSymbols", "optNoAmbiguous",
     "wOptDigits", "wOptCaps"].forEach(function (id) {
      $(id).addEventListener("change", generate);
    });

    Array.prototype.forEach.call(document.querySelectorAll('input[name="sep"]'), function (el) {
      el.addEventListener("change", generate);
    });
    Array.prototype.forEach.call(document.querySelectorAll('input[name="mode"]'), function (el) {
      el.addEventListener("change", switchMode);
    });

    $("attacker").addEventListener("change", generate);
    $("copyBtn").addEventListener("click", copyPassword);
    $("regenBtn").addEventListener("click", generate);

    document.addEventListener("keydown", function (e) {
      if (e.key === " " && e.target === document.body) { e.preventDefault(); generate(); }
    });

    $("charLenValue").textContent = $("charLen").value;
    $("wordCountValue").textContent = $("wordCount").value;
    generate();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
