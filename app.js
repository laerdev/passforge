/* Passphrase Forge, v1. All generation happens locally in the browser. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };

  /* ---------- cryptographic randomness ---------- */
  function randomInt(max) {                     // uniform in [0, max), unbiased
    if (max <= 0) { return 0; }
    var limit = Math.floor(4294967296 / max) * max;
    var buf = new Uint32Array(1);
    var v;
    do {
      crypto.getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }
  function pick(arr) { return arr[randomInt(arr.length)]; }

  /* ---------- character pools ---------- */
  var LOWER = "abcdefghijklmnopqrstuvwxyz";
  var UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  var DIGITS = "0123456789";
  var SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
  var AMBIGUOUS = "O0oIl1|`'\"{}[]();:,.";
  var PHRASE_SYMBOLS = "!?@#$%&*+=";

  function charPool() {
    var pool = "";
    if ($("optLower").checked) { pool += LOWER; }
    if ($("optUpper").checked) { pool += UPPER; }
    if ($("optDigits").checked) { pool += DIGITS; }
    if ($("optSymbols").checked) { pool += SYMBOLS; }
    if ($("optAmbiguous").checked) {
      pool = pool.split("").filter(function (c) { return AMBIGUOUS.indexOf(c) === -1; }).join("");
    }
    return pool;
  }

  /* ---------- generators ---------- */
  function generateRandom() {
    var pool = charPool();
    var len = parseInt($("length").value, 10);
    if (!pool.length) { return { text: "", bits: 0, empty: true }; }
    var out = "";
    for (var i = 0; i < len; i++) { out += pool.charAt(randomInt(pool.length)); }
    return { text: out, bits: len * Math.log(pool.length) / Math.LN2, pool: pool.length };
  }

  var sepButtons = [].slice.call(document.querySelectorAll(".sep-btn"));

  function sepChoice() {
    for (var i = 0; i < sepButtons.length; i++) {
      if (sepButtons[i].getAttribute("aria-pressed") === "true") { return sepButtons[i].dataset.sep; }
    }
    return "-";
  }

  function separatorValue() {
    var sel = sepChoice();
    if (sel !== "custom") { return sel; }
    var custom = $("separatorCustom").value;
    return custom.length ? custom.charAt(0) : "-";
  }

  var SEP_HINTS = {
    "-": "Hyphen keeps the words readable and works in almost every password field.",
    ".": "A period reads cleanly and is accepted just about everywhere.",
    "_": "The underscore is a safe pick for systems that dislike punctuation.",
    "+": "Plus signs are fine for most logins, though a few older forms reject them.",
    "/": "Slashes are unusual, which helps, but check the field accepts them.",
    " ": "Spaces are allowed by most modern sites and make the phrase easy to read aloud.",
    "": "No spacing character means one long string: shorter to type, harder to read back.",
    "custom": "Type any single character to use as the spacing character."
  };

  function generatePhrase() {
    var count = parseInt($("wordCount").value, 10);
    var sep = separatorValue();
    var caps = $("phraseCaps").checked;
    var bits = count * Math.log(WORDS.length) / Math.LN2;

    var tokens = [];
    for (var i = 0; i < count; i++) {
      var w = WORDS[randomInt(WORDS.length)];
      tokens.push(caps ? w.charAt(0).toUpperCase() + w.slice(1) : w);
    }
    if ($("phraseNumbers").checked) {
      var num = randomInt(100);
      var slot = randomInt(tokens.length + 1);            // any position, including the ends
      tokens.splice(slot, 0, num < 10 ? "0" + num : String(num));
      bits += Math.log(100 * (count + 1)) / Math.LN2;
    }
    var text = tokens.join(sep);
    if ($("phraseSymbol").checked) {
      text += PHRASE_SYMBOLS.charAt(randomInt(PHRASE_SYMBOLS.length));
      bits += Math.log(PHRASE_SYMBOLS.length) / Math.LN2;
    }
    var extras = [];
    if ($("phraseNumbers").checked) { extras.push("a two digit number"); }
    if ($("phraseSymbol").checked) { extras.push("one symbol"); }
    return {
      text: text,
      bits: bits,
      words: count,
      extras: extras.length ? " plus " + extras.join(" and ") : ""
    };
  }

  /* ---------- time formatting ---------- */
  var MINUTE = 60, HOUR = 3600, DAY = 86400, YEAR = 31557600;
  var BIG = [
    { n: 1e3, label: "thousand" }, { n: 1e6, label: "million" }, { n: 1e9, label: "billion" },
    { n: 1e12, label: "trillion" }, { n: 1e15, label: "quadrillion" }, { n: 1e18, label: "quintillion" }
  ];

  function round(x) { return x < 10 ? Math.round(x * 10) / 10 : Math.round(x); }

  function formatDuration(seconds) {
    if (!isFinite(seconds)) { return "essentially forever"; }
    if (seconds < 1) { return "instantly"; }
    if (seconds < MINUTE) { return round(seconds) + " seconds"; }
    if (seconds < HOUR) { return round(seconds / MINUTE) + " minutes"; }
    if (seconds < DAY) { return round(seconds / HOUR) + " hours"; }
    if (seconds < DAY * 60) { return round(seconds / DAY) + " days"; }
    if (seconds < YEAR) { return round(seconds / (DAY * 30.44)) + " months"; }
    var years = seconds / YEAR;
    if (years < 1e3) { return round(years) + " years"; }
    for (var i = BIG.length - 1; i >= 0; i--) {
      if (years >= BIG[i].n && years < BIG[i].n * 1e3) {
        return round(years / BIG[i].n) + " " + BIG[i].label + " years";
      }
    }
    var exp = Math.floor(Math.log(years) / Math.LN10);
    var mant = years / Math.pow(10, exp);
    return (Math.round(mant * 10) / 10) + " x 10^" + exp + " years";
  }

  function crackSeconds(bits, rate) {
    var log10Guesses = bits * Math.log(2) / Math.LN10 - Math.log(2) / Math.LN10;  // half the space
    var log10Seconds = log10Guesses - Math.log(rate) / Math.LN10;
    if (log10Seconds > 308) { return Infinity; }
    return Math.pow(10, log10Seconds);
  }

  /* ---------- rendering ---------- */
  function renderOutput(text) {
    var box = $("output");
    box.textContent = "";
    for (var i = 0; i < text.length; i++) {
      var c = text.charAt(i);
      var span = document.createElement("span");
      if (DIGITS.indexOf(c) !== -1) { span.className = "digits"; }
      else if (!/[a-zA-Z]/.test(c)) { span.className = "sym"; }
      span.textContent = c;
      box.appendChild(span);
    }
  }

  function strengthLevel(bits) {
    if (bits < 36) { return { key: "weak", label: "Weak" }; }
    if (bits < 60) { return { key: "fair", label: "Fair" }; }
    if (bits < 90) { return { key: "good", label: "Strong" }; }
    return { key: "great", label: "Very strong" };
  }

  var ADVICE = {
    weak: "<b>Too easy to crack.</b> Fine for a throwaway login, not for anything you care about.",
    fair: "<b>Holds up online, not offline.</b> Good enough for a low value account. Add a word, or a few characters, before using it anywhere important.",
    good: "<b>Solid.</b> Safe for everyday accounts, email and shopping.",
    great: "<b>Excellent.</b> Out of reach of any realistic attack, including a well funded one. Store it in a password manager."
  };

  var current = "";

  function update() {
    var mode = document.body.dataset.mode;
    var result = mode === "random" ? generateRandom() : generatePhrase();
    current = result.text;
    $("output").scrollLeft = 0;

    if (result.empty) {
      $("output").textContent = "Turn on at least one character set";
      $("entropyBits").textContent = "0";
      $("meterFill").style.width = "0%";
      $("entropyNote").textContent = "No character sets selected, so there is nothing to generate.";
      $("crackOnline").textContent = $("crackOffline").textContent = $("crackFast").textContent = "-";
      $("strengthTag").textContent = "Empty";
      $("strengthTag").dataset.level = "weak";
      $("meterFill").dataset.level = "weak";
      $("advice").textContent = "Switch on lowercase, uppercase, numbers or symbols to build a password.";
      return;
    }

    renderOutput(result.text);

    var bits = result.bits;
    $("entropyBits").textContent = bits.toFixed(1);
    $("meterFill").style.width = Math.min(100, (bits / 160) * 100).toFixed(1) + "%";

    var level = strengthLevel(bits);
    $("strengthTag").textContent = level.label;
    $("strengthTag").dataset.level = level.key;
    $("meterFill").dataset.level = level.key;
    $("advice").innerHTML = ADVICE[level.key];

    var combos = "2^" + Math.round(bits) + " possible passwords";
    $("entropyNote").textContent = mode === "random"
      ? result.text.length + " characters drawn from a pool of " + result.pool + ", about " + combos + "."
      : result.words + " words from a list of 7,776" + result.extras + ", about " + combos + ".";

    $("crackOnline").textContent = formatDuration(crackSeconds(bits, 100));
    $("crackOffline").textContent = formatDuration(crackSeconds(bits, 1e10));
    $("crackFast").textContent = formatDuration(crackSeconds(bits, 1e14));

    if (mode === "random") {
      $("poolHint").textContent = "Pool: " + result.pool + " characters, " +
        (Math.log(result.pool) / Math.LN2).toFixed(2) + " bits per character.";
    }
  }

  /* ---------- interactions ---------- */
  function setMode(mode) {
    document.body.dataset.mode = mode;
    var phrase = mode === "phrase";
    $("panel-phrase").hidden = !phrase;
    $("panel-random").hidden = phrase;
    $("tab-phrase").classList.toggle("is-active", phrase);
    $("tab-random").classList.toggle("is-active", !phrase);
    $("tab-phrase").setAttribute("aria-selected", String(phrase));
    $("tab-random").setAttribute("aria-selected", String(!phrase));
    update();
  }

  $("tab-phrase").addEventListener("click", function () { setMode("phrase"); });
  $("tab-random").addEventListener("click", function () { setMode("random"); });
  $("regenerate").addEventListener("click", update);

  $("wordCount").addEventListener("input", function () {
    $("wordCountValue").textContent = this.value;
    update();
  });
  $("length").addEventListener("input", function () {
    $("lengthValue").textContent = this.value;
    update();
  });
  function selectSeparator(sep) {
    sepButtons.forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.sep === sep)); });
    $("separatorCustom").classList.toggle("is-idle", sep !== "custom");
    $("sepHint").textContent = SEP_HINTS[sep];
    update();
  }

  sepButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      selectSeparator(btn.dataset.sep);
      if (btn.dataset.sep === "custom") { $("separatorCustom").focus(); }
    });
  });
  $("separatorCustom").addEventListener("input", function () { selectSeparator("custom"); });
  $("separatorCustom").addEventListener("focus", function () {
    if (sepChoice() !== "custom" && this.value.length) { selectSeparator("custom"); }
  });

  ["phraseNumbers", "phraseCaps", "phraseSymbol", "optLower", "optUpper", "optDigits", "optSymbols", "optAmbiguous"]
    .forEach(function (id) { $(id).addEventListener("change", update); });

  /* copy */
  function flashCopied(ok) {
    var status = $("copyStatus");
    status.textContent = ok ? "Copied to clipboard" : "Copy failed, select the text instead";
    status.style.color = ok ? "" : "var(--bad)";
    status.classList.add("show");
    setTimeout(function () { status.classList.remove("show"); }, 2200);
  }
  function legacyCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }
  $("copy").addEventListener("click", function () {
    if (!current) { return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(current).then(function () { flashCopied(true); },
        function () { flashCopied(legacyCopy(current)); });
    } else {
      flashCopied(legacyCopy(current));
    }
  });

  /* theme, light by default, choice remembered */
  var toggle = $("themeToggle");
  var stored = null;
  try { stored = localStorage.getItem("pf-theme"); } catch (e) { stored = null; }
  var dark = stored === "dark";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  toggle.checked = dark;
  toggle.addEventListener("change", function () {
    var on = this.checked;
    document.documentElement.dataset.theme = on ? "dark" : "light";
    try { localStorage.setItem("pf-theme", on ? "dark" : "light"); } catch (e) { /* ignore */ }
  });

  /* keyboard shortcut: space or enter on the output regenerates */
  $("output").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { e.preventDefault(); update(); }
  });

  setMode("phrase");
})();
