<?lsp
response:setheader("Cache-Control","no-store")
response:setheader("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
response:setheader("X-Content-Type-Options","nosniff")
response:setheader("Referrer-Policy","no-referrer")
local httpsPort=ba.serversslport or tonumber(require"loadconf".sslport) or 443
?>
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title><?lsp=pageTitle?> | SharkTrust Private CA</title>
<link rel="stylesheet" href="/assets/style.css">
<link rel="stylesheet" href="/assets/portal.css">
<script src="/assets/dashboard.js" defer></script>
<script src="/assets/portal.js" defer></script></head>
<body data-view="<?lsp=pageView?>" data-https-port="<?lsp=httpsPort?>">
<div id="layout" class="app-shell">
<button id="menuLink" class="menu-link" type="button" aria-label="Toggle navigation" aria-controls="menu" aria-expanded="false"><span></span></button>
<aside id="menu" class="side-nav" aria-label="Primary navigation"><div class="nav-inner">
<a class="nav-brand" href="/"><span class="brand-mark">CA</span><span class="brand-copy"><strong>SharkTrust</strong><small>Private CA</small></span></a>
<nav id="navigation" hidden><ul class="nav-list">
<?lsp for _,item in ipairs(pageMenu) do ?>
<li class="nav-item"<?lsp= item[1]~='available' and item[1]~='account' and ' data-admin-nav hidden' or ''?>><a class="nav-link<?lsp=pageView==item[1] and ' is-active' or ''?>" href="<?lsp=item[1]=='overview' and '/' or '/'..item[1]..'.lsp'?>"<?lsp=pageView==item[1] and ' aria-current="page"' or ''?>><?lsp=item[2]?></a></li>
<?lsp end ?>
</ul></nav>
<div class="nav-account"><div class="account-name" id="accountName">Administrator sign-in</div><button id="logout" class="nav-account-link quiet" hidden>Sign out</button></div>
</div></aside>
<main id="main" class="main-pane">
<header class="page-header"><div><p class="eyebrow">SharkTrust Private CA</p><h1 id="pageTitle"><?lsp=pageTitle?></h1></div>
<div class="page-meta"><nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/">Home</a><span id="breadcrumb"><?lsp=pageTitle?></span></nav><span id="status" class="badge">Connecting</span></div></header>
<section class="content"><div id="notice" role="status" hidden></div>
<section id="auth" class="auth-card" hidden>
<span class="eyebrow">YOUR PRIVATE TRUST INFRASTRUCTURE</span><h1 id="authTitle">Welcome to SharkTrust</h1><p id="authIntro"></p>
<form id="authForm"><label>Administrator username<input id="username" autocomplete="username" required maxlength="64" pattern="[A-Za-z0-9_.\-]+"></label><label>Administrator password<input id="password" type="password" autocomplete="current-password" required maxlength="128"></label>
<div id="setupFields" hidden><label>Confirm password<input id="confirmPassword" type="password" autocomplete="new-password" maxlength="128"></label>
<label>Network grouping<select id="networkMode"><option value="local">Local network — one shared namespace</option><option value="wan">Cloud portal — group devices by WAN address</option></select></label>
<p class="hint">Choose where the portal runs. A device must be factory reset before moving to another network.</p></div>
<button class="primary" id="authSubmit" type="submit">Sign in</button></form><p><a id="ssoLogin" class="button" href="/ms-sso.lsp?start=1" hidden>Sign in with Microsoft</a></p></section>

<section id="workspace" hidden><div class="title-row"><p id="pageSubtitle"></p><button id="refresh">Refresh</button></div><div id="content"></div></section>
<noscript>Enable JavaScript to use portal administration.</noscript></section>
<footer class="site-footer"><span>Private trust. Local control.</span><span>ECC · TPM protected</span></footer>
</main></div>
<div id="toastRegion" class="toast-region" aria-live="polite" aria-atomic="true"></div>
<dialog id="dialog"><div class="dialog-heading"><h2 id="dialogTitle"></h2><button id="closeDialog" aria-label="Close dialog">×</button></div><p id="dialogNotice" role="alert" hidden></p><div id="dialogBody"></div></dialog>
</body></html>
