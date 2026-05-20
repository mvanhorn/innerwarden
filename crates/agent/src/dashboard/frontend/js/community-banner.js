// community-banner.js — Spec 051 PR1
//
// In-dashboard call-to-action that asks operators to voluntarily share
// they're running Inner Warden. Inner Warden has no phone-home telemetry
// by design; the cost is that the project owner has no signal whether
// the project is helping anyone. This banner converts SOME silent users
// into ones who reply, without changing the "nothing leaves your box"
// branding (no data is ever sent from this module — all links are
// outbound clicks the operator initiates).
//
// Pure helpers exposed for testability: `shouldShowCommunityBanner`,
// `dismissForever`, and `remindIn30Days` all take their `storage`
// dependency explicitly so unit tests can pass a mock Map instead of
// `window.localStorage`. The DOM-attached render path lives in home.js;
// this file owns the state machine.
//
// localStorage keys (chosen to avoid collisions with future surfaces):
//   - `iw:community-banner:dismissed`       = "true" if dismissed forever
//   - `iw:community-banner:remind-until`    = ISO timestamp; hide until then
//
// Three dismiss states (spec §3.2):
//   1. No action / scroll past  → banner stays, re-renders every Home load
//   2. Remind me in 30 days     → banner hidden until ts > remind-until
//   3. Hide forever             → banner never re-renders on this browser

var COMMUNITY_BANNER_DISMISSED_KEY = 'iw:community-banner:dismissed';
var COMMUNITY_BANNER_REMIND_KEY    = 'iw:community-banner:remind-until';
var COMMUNITY_BANNER_REMIND_MS     = 30 * 24 * 60 * 60 * 1000;

// True iff the banner should render right now. Pure: caller passes
// `now` (Date or ms) and a storage handle (an object exposing
// `getItem(key)` — matches the localStorage shape). When `storage` is
// null/undefined/unavailable the banner ALWAYS shows (spec §4: must
// still function with storage disabled, no console errors).
function shouldShowCommunityBanner(now, storage) {
  if (!storage) return true;
  try {
    if (storage.getItem(COMMUNITY_BANNER_DISMISSED_KEY) === 'true') {
      return false;
    }
    var remindUntilRaw = storage.getItem(COMMUNITY_BANNER_REMIND_KEY);
    if (remindUntilRaw) {
      var remindUntilMs = Date.parse(remindUntilRaw);
      var nowMs = (now instanceof Date) ? now.getTime() : (now || Date.now());
      if (!isNaN(remindUntilMs) && remindUntilMs > nowMs) {
        return false;
      }
    }
  } catch (_e) {
    // storage threw (private-mode Safari, quota error, etc.). Spec §4
    // says the banner must still function — treat as visible rather
    // than swallowing the user-visible feature on every load.
    return true;
  }
  return true;
}

// Store the "hide forever" decision. Pure: caller passes the storage
// handle. Returns true if the write succeeded.
function dismissForever(storage) {
  if (!storage) return false;
  try {
    storage.setItem(COMMUNITY_BANNER_DISMISSED_KEY, 'true');
    return true;
  } catch (_e) {
    return false;
  }
}

// Store the "remind in 30 days" decision. Pure: caller passes the
// current time and the storage handle. Returns true on success.
function remindIn30Days(now, storage) {
  if (!storage) return false;
  try {
    var nowMs = (now instanceof Date) ? now.getTime() : (now || Date.now());
    var untilIso = new Date(nowMs + COMMUNITY_BANNER_REMIND_MS).toISOString();
    storage.setItem(COMMUNITY_BANNER_REMIND_KEY, untilIso);
    return true;
  } catch (_e) {
    return false;
  }
}

// DOM-attached render. Called from home.js on every Home load.
// Side-effect: toggles the `#homeCommunityBanner` element's display
// based on `shouldShowCommunityBanner`, and wires the dismiss buttons.
//
// Idempotent — clicking handlers re-attached every render are
// harmless because the buttons replace their `onclick` rather than
// addEventListener-stacking.
function renderCommunityBanner() {
  var banner = (typeof document !== 'undefined')
    ? document.getElementById('homeCommunityBanner')
    : null;
  if (!banner) return;

  var storage = null;
  try { storage = (typeof window !== 'undefined') ? window.localStorage : null; }
  catch (_e) { storage = null; }

  if (!shouldShowCommunityBanner(new Date(), storage)) {
    banner.style.display = 'none';
    return;
  }
  banner.style.display = '';

  var remindBtn = banner.querySelector('.community-banner-remind');
  if (remindBtn) {
    remindBtn.onclick = function () {
      remindIn30Days(new Date(), storage);
      banner.style.display = 'none';
    };
  }
  var dismissBtn = banner.querySelector('.community-banner-dismiss');
  if (dismissBtn) {
    dismissBtn.onclick = function () {
      dismissForever(storage);
      banner.style.display = 'none';
    };
  }
}

// CommonJS export: kept so a future jsdom-based test runner can
// `require('./community-banner')` to exercise the pure helpers. The
// browser ignores this guard (module is undefined) and the functions
// remain on the global scope for home.js to call.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    shouldShowCommunityBanner: shouldShowCommunityBanner,
    dismissForever: dismissForever,
    remindIn30Days: remindIn30Days,
    renderCommunityBanner: renderCommunityBanner,
    COMMUNITY_BANNER_DISMISSED_KEY: COMMUNITY_BANNER_DISMISSED_KEY,
    COMMUNITY_BANNER_REMIND_KEY: COMMUNITY_BANNER_REMIND_KEY,
    COMMUNITY_BANNER_REMIND_MS: COMMUNITY_BANNER_REMIND_MS,
  };
}
