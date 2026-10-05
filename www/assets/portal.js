'use strict';

const $ = id => document.getElementById(id);

const list = value => Array.isArray(value) ? value : [];

let selectedZone=new URLSearchParams(location.search).get("zone")||undefined, state, snapshot, view = document.body.dataset.view, secretTimer;

const titles = {overview:'Overview',zones:'Zones',devices:'All devices',certificates:'Certificates',authorities:'Certificate authority',activity:'Activity',account:'Administrator'};

const subtitles = {overview:'Manage private certificates for your devices.',zones:'Enrollment credentials and certificate address policies.',devices:'Registered identities and their current network groups.',certificates:'Certificates issued by your private authority.',authorities:'The trust root for this portal.',activity:'Recent enrollment and administration events.',account:'Manage your sign-in credentials.'};

function el(tag, text, className) { const node=document.createElement(tag); if(text!==undefined)node.textContent=text; if(className)node.className=className; return node; }

function notice(message,error=false) { const box=$('dialog').open ? $('dialogNotice') : $('notice'); if(box){box.textContent=message || '';box.classList.toggle('error',error);box.hidden=!message;} }

function date(value) { return value ? new Date(Number(value)*1000).toLocaleString() : '—'; }

function button(text, handler, className) { const b=el('button',text,className); b.type='button'; b.addEventListener('click',()=>run(handler,b)); return b; }

async function run(handler, control) { if(control)control.disabled=true; try { notice(''); await handler(); } catch(e) { notice(e.message,true); } finally { if(control)control.disabled=false; } }

async function api(action, data={}) {

  if(action?.startsWith('ca') || action==='dashboard')data={zoneId:selectedZone,...data};
  const response=await fetch('/admin.lsp',action ? {method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':state.csrf},body:JSON.stringify({action,...data})} : {cache:'no-store'});

  if(response.ok && action==='zoneCode')return response.blob();

  const result=await response.json();

  if(!response.ok) { if(response.status===401 && !['login','zoneSecret','zoneCode','credentials','adminAddress','notificationTest','caPrepare','caActivate','caDiscard','caCsr','caRotate','caImport'].includes(action))await initialize(); throw Error(result.error || 'Request failed'); }

  return result;

}

function closeDialog() { clearTimeout(secretTimer); $('dialog').close(); $('dialogBody').replaceChildren(); }

function dialog(title) { closeDialog(); $('dialogTitle').textContent=title; $('dialogNotice').hidden=true;$('dialog').showModal(); return $('dialogBody'); }

function field(form,label,type='text',value='') { const wrap=el('label',type==='checkbox'?undefined:label),input=el('input'); input.type=type; input.value=value; wrap.append(input); if(type==='checkbox'){wrap.className='check-field';wrap.append(el('span',label));} form.append(wrap); return input; }

function table(headers,rows,empty) {

  if(!rows.length)return el('div',empty,'empty');

  const wrapper=el('div',undefined,'table-wrap'),t=el('table'),head=el('thead'),hr=el('tr'),body=el('tbody');

  headers.forEach(h=>hr.append(el('th',h)));head.append(hr);t.append(head,body);

  rows.forEach(cells=>{const tr=el('tr');cells.forEach(cell=>{const td=el('td');td.append(cell instanceof Node ? cell : document.createTextNode(String(cell??'—')));tr.append(td);});body.append(tr);});

  wrapper.append(t);return wrapper;

}

function panel(title) { const p=el('section',undefined,'panel');if(title)p.append(el('h2',title));return p; }

function link(text,url) { const a=el('a',text,'button');a.href=url;return a; }

function selectView(name) { location.assign(name==='overview'?'/':'/'+name+'.lsp'); }

async function refresh() {
  if(view==='available'){
    const result=await api('available'),content=$('content');
    $('pageSubtitle').textContent='Registered devices on your network for this portal address.';
    content.replaceChildren(el('p','Open a device using its HTTPS link. Your browser must trust its zone CA; .local names also require mDNS support on your network. This list does not check whether devices are online.','hint'));
    content.append(table(['Device','IP address'],list(result.devices).map(d=>{
      const a=el('a',d.name);a.href='https://'+d.name+'/';a.target='_blank';a.rel='noopener noreferrer';return [a,d.ip];
    }),'No devices are registered for your network at this portal address.'));
    return;
  }
  snapshot=await api('dashboard');selectedZone=snapshot.selectedZone;render();
}

function render() {

  $('pageTitle').textContent=titles[view];$('accountName').textContent=snapshot.username;$('pageSubtitle').textContent=subtitles[view];$('breadcrumb').textContent='Workspace / '+titles[view];

  $('status').textContent=snapshot.ready ? 'Issuer ready' : 'Issuer starting';



  const content=$('content');content.replaceChildren();
  if(snapshot.role==='site' && !['account','zones'].includes(view)){
    const label=el('label',view==='authorities'?'Certificate authority':'Zone filter'),select=el('select');select.setAttribute('aria-label',view==='authorities'?'Certificate authority':'Zone filter');
    const all=el('option',view==='authorities'?'Portal HTTPS CA':'All zones');all.value='';select.append(all);
    list(snapshot.zones).forEach(z=>{const option=el('option',z.name);option.value=z.id;select.append(option);});
    select.value=selectedZone||'';select.addEventListener('change',()=>run(async()=>{selectedZone=select.value||undefined;await refresh();}));label.append(select);content.append(label);
  }
  const zoneName=id=>list(snapshot.zones).find(z=>z.id===id)?.name || id || 'Portal';

  if(view==='overview') {

    const cards=el('div',undefined,'cards');

    [['Registered devices',snapshot.deviceCount,'Names and addresses enrolled'],['Certificates issued',snapshot.certificateCount,'Signed by this private CA'],['Enrollment zones',list(snapshot.zones).length,'Each with independent credentials']].forEach(([title,note,caption])=>{const c=el('div',undefined,'card');c.append(el('div',title,'label'),el('div',note,'number'),el('div',caption,'hint'));cards.append(c);});content.append(cards);

    const grid=el('div',undefined,'grid'),start=panel('Connect your first device');start.append(el('p','Open a zone to retrieve its enrollment key and secret. Use this portal’s ACME directory for that device.'));

    const actions=el('div',undefined,'actions');actions.append(button('Manage zones',()=>selectView('zones'),'primary'),button('Download trust root',()=>selectView('authorities')));start.append(actions);

    const details=panel('Portal details');details.append(el('p',snapshot.origin),el('p',snapshot.networkMode==='local'?'Local network · one shared namespace':'Cloud portal · automatic WAN grouping'),el('p','TPM-managed ECC signing keys','hint'),el('p','Portal HTTPS certificate: '+(snapshot.listener?.status||'pending'),'hint'));

    grid.append(start,details);content.append(grid);

    const scope=panel('Development status');scope.append(el('p','Enrollment, ACME issuance, root renewal and administration are available. Each zone has its own issuing CA and administrators. CA import and rotation are available. Certificate revocation services are out of scope. Mako client integration is tested; Xedge and ESP32 acceptance remain.'));content.append(scope);

  } else if(view==='zones') {

    const toolbar=el('div',undefined,'zone-toolbar');toolbar.append(el('p','Each zone has its own CA, enrollment credentials and device certificate policy.'));if(snapshot.role==='site')toolbar.append(button('Create zone',createZone,'primary'));content.append(toolbar);

    const zones=list(snapshot.zones),cards=el('div',undefined,'zone-list');

    zones.forEach(z=>{

      const card=el('article',undefined,'zone-card'),heading=el('div',undefined,'zone-heading'),identity=el('div',undefined,'zone-identity');

      const title=el('h2',z.name);title.id='zone-'+z.id;card.setAttribute('aria-labelledby',title.id);

      identity.append(title,el('div',z.portalUrl||'Address required','zone-address'));

      const status=z.tlsStatus?.status||'pending',badge=el('span',status==='installed'?'HTTPS active':'HTTPS · '+status,'zone-status');if(status!=='installed')badge.classList.add('pending');heading.append(identity,badge);

      const details=el('dl',undefined,'zone-details');

      [['Portal certificate',z.tls?.issuer==='letsencrypt'?"Let’s Encrypt":'SharkCA'],['Device certificates',z.includeIp?'Name and/or IP address':'Name · .local'],['Registered devices',z.devices]].forEach(([label,value])=>{const item=el('div');item.append(el('dt',label),el('dd',value));details.append(item);});

      card.append(heading,details);

      if(z.includeIp)card.append(el('p','Allowed IP ranges: '+list(z.allowedRanges).join(', '),'zone-ranges'));

      if(z.tlsStatus?.error)card.append(el('p',z.tlsStatus.error,'zone-error'));

      const actions=el('div',undefined,'zone-actions'),main=el('div',undefined,'zone-action-group'),manage=el('div',undefined,'zone-action-group');

      main.append(button('Download C code',()=>showCredentials(z,true),'primary'),button('Credentials',()=>showCredentials(z)),button('Configure HTTPS',()=>zoneWizard(z)),button('Certificate authority',()=>location.assign('/authorities.lsp?zone='+z.id)));

      manage.append(button('Edit policy',()=>editPolicy(z),'quiet'),button('Clean inactive devices',()=>previewCleanup(z),'quiet'),button('Delete zone',()=>deleteZone(z),'quiet danger'));actions.append(main,manage);card.append(actions);cards.append(card);

    });

    content.append(zones.length?cards:el('div','No zones yet. Create a zone to connect your devices.','empty'),el('p','Viewing credentials or downloading C code requires your administrator password.','hint'));



  } else if(view==='devices') {

    const p=panel();p.append(el('p','Showing up to 200 most recently active devices. A WAN conflict blocks issuance until the grouping problem is resolved. Delete removes a registration and frees its name; issued certificates remain valid.','hint'));

    p.append(table(['Name','Device IP','WAN / group','Last seen','Status','Actions'],list(snapshot.devices).map(d=>[d.label?d.label+'.local':'IP only',d.local_ip,d.wan+' / '+d.group_id,date(d.last_seen),Number(d.conflicted)?'Network conflict':'Registered',button('Delete',()=>deleteDevice(d),'quiet danger')]),'No devices registered. Start by opening a zone and retrieving its enrollment credentials.'));content.append(p);

  } else if(view==='certificates') {

    const p=panel();p.append(el('p','Showing the latest 200 issued certificates. Removing a device does not revoke an issued certificate. For compromised trust, remove the CA from client trust stores and delete the affected zone.','hint'));

    p.append(table(['Zone','Serial','Identifiers','Expires','SHA-256'],list(snapshot.certificates).map(c=>[zoneName(c.zone_id),c.serial,list(JSON.parse(c.identifiers||'[]')).map(i=>i.value).join(', '),date(c.not_after),c.fingerprint]),'No certificates issued yet.'));content.append(p);

  } else if(view==='authorities') {

    const p=panel('Trust root');p.append(el('p','Select a zone to manage its device CA and download its trust root. The separate Portal HTTPS CA signs the web interface when private HTTPS is selected. Trusting the portal CA does not trust zone devices. Private keys remain in the TPM.'));

    p.append(el('h3',selectedZone?zoneName(selectedZone):'Portal HTTPS CA'),button('Download root PEM',()=>caDownload('active')));content.append(p);

    const ca=snapshot.lifecycle||{},renewal=panel('CA lifetime and renewal');
    renewal.append(el('p','Status: '+(ca.state||'unavailable')+' · '+(ca.daysRemaining??'—')+' days remaining'),el('p','Renew before '+date(ca.renewBefore)+' to keep issuing certificates with their full configured lifetime.'),el('p','Root renewal extends validity using the same TPM key. Key rotation creates a new key and trust root. For an external intermediate, create a new CSR and have your CA sign it. Provision the prepared trust before activation.'));
    if(ca.fingerprint)renewal.append(el('p','Active certificate file SHA-256','hint'),el('pre',ca.fingerprint));
    if(ca.pending){
      renewal.append(el('h3',ca.pending.newKey?'Prepared CA key rotation':'Prepared root renewal'),el('p','Expires: '+date(ca.pending.expiresAt)),el('p','Prepared issuer certificate file SHA-256','hint'),el('pre',ca.pending.fingerprint),el('p','Trust root file SHA-256','hint'),el('pre',ca.pending.trustFingerprint));
      const actions=el('div',undefined,'actions');actions.append(button('Download prepared trust root',()=>caDownload('renewal')),button('Activate prepared CA',()=>{
        const body=dialog('Activate prepared CA'),form=el('form');
        body.append(el('p','Only the selected CA changes. Existing registrations and certificate history are retained. Keep the old trust root until its certificates have been replaced or expired. Activation does not force device renewal. Changing the Portal HTTPS CA also replaces private web certificates; provision that trust in your browser first.'));
        const accepted=field(form,'I have provisioned the prepared trust root to relying clients','checkbox');accepted.required=true;
        const password=field(form,'Confirm administrator password','password');password.required=true;password.autocomplete='current-password';
        const submit=el('button','Activate','primary');submit.type='submit';form.append(submit);body.append(form);
        form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{const result=await api('caActivate',{password:password.value,acknowledge:accepted.checked,fingerprint:ca.pending.fingerprint});closeDialog();await refresh();notice(result.warning||'Prepared CA activated.');},submit);});
      },'primary'),button('Discard prepared CA',()=>caAction('caDiscard','Discard prepared CA'),'danger'));renewal.append(actions);
    }else {
      if(ca.kind!=='intermediate')renewal.append(button('Prepare root renewal',()=>caAction('caPrepare','Prepare root renewal'),'primary'));
      renewal.append(button('Prepare new root key',()=>caAction('caRotate','Prepare new root key')));
    }
    content.append(renewal);
    const intermediate=panel('External intermediate CA');intermediate.append(el('p','Create a CSR for a separate TPM-backed ECC key. Have your CA sign it as a certificate authority permitted to sign TLS server certificates. Keep this portal state and TPM identity while the CSR is being signed. Import the signed certificate and parent chain below, then review and activate the prepared CA.'),el('p','Import supports unrestricted X.509 v3 CA chains with ECC P-256/P-384 issuing keys. Name constraints, certificate-policy extensions, extended key usage and unsupported critical extensions are rejected.','hint'));
    if(ca.csrReady){
      intermediate.append(button('Download intermediate CSR',()=>caDownload('csr')));
      if(!ca.pending)intermediate.append(button('Import signed intermediate',importCa,'primary'));
    }
    else intermediate.append(button('Create intermediate CSR',()=>caAction('caCsr','Create intermediate CSR')));
    content.append(intermediate);
    if(list(ca.retired).length){
      const history=panel('Previous authorities');history.append(el('p','Keep these roots trusted while their certificates remain in use, unless a key was compromised. These authorities no longer issue certificates.','hint'));
      history.append(table(['Retired','Expires','Trust root'],list(ca.retired).map(c=>[date(c.retired),date(c.expiresAt),button('Download',()=>caDownload('history',c.fingerprint))])));content.append(history);
    }
    const urls=panel('Zone ACME directories');list(snapshot.zones).filter(z=>z.portalUrl).forEach(z=>urls.append(el('h3',z.name),el('pre',z.portalUrl+'/acme/directory')));content.append(urls);

  } else if(view==='account') {
    if(snapshot.role==='site'){
      const users=panel('Zone administrators');users.append(el('p','Each account manages one zone. Saving or deleting an account signs out all browser sessions. A password reset clears its Microsoft link.'),button('Add zone administrator',()=>editUser(),'primary'));
      users.append(table(['Username','Zone','Actions'],list(snapshot.users).map(u=>{const actions=el('div',undefined,'actions');actions.append(button('Reset or reassign',()=>editUser(u)),button('Delete',()=>confirmPassword('Delete zone administrator',async password=>{await api('userDelete',{username:u.username,password});closeDialog();await initialize();}),'danger'));return [u.username,zoneName(u.zoneId),actions];}),'No zone administrators.'));
      content.append(users);
    }

    const p=panel('Change administrator credentials'),form=el('form');
    const username=field(form,'Administrator username','text',snapshot.username);username.required=true;username.maxLength=64;username.autocomplete='username';username.pattern='[A-Za-z0-9_.\\-]+';
    const current=field(form,'Current password','password');current.required=true;current.autocomplete='current-password';current.maxLength=128;
    const password=field(form,'New password','password');password.required=true;password.minLength=12;password.maxLength=128;password.autocomplete='new-password';
    const confirm=field(form,'Confirm new password','password');confirm.required=true;confirm.maxLength=128;confirm.autocomplete='new-password';
    const submit=el('button','Save credentials','primary');submit.type='submit';form.append(submit);
    form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{
      if(password.value!==confirm.value)throw Error('Passwords do not match.');
      await api('credentials',{username:username.value,password:current.value,newPassword:password.value});
      form.reset();snapshot=null;view='overview';$('content').replaceChildren();await initialize();notice('Credentials updated. Sign in again.');
    },submit);});
    p.append(el('p','Changing credentials signs out every browser session. Your CA, zones and devices are retained.'),form);content.append(p);
    const sso=panel('Microsoft sign-in');
    sso.append(el('p',snapshot.sso?.linked?'A Microsoft account is linked to this administrator.':'Link your Microsoft account to sign in without entering the local password. Sensitive actions still require your local password.'));
    if(snapshot.sso?.addressReady)sso.append(button(snapshot.sso.linked?'Replace linked account':'Link Microsoft account',()=>confirmPassword('Link Microsoft account',async password=>{const result=await api('ssoLink',{password});location.assign(result.url);})));
    else sso.append(el('p','The server operator must configure openid in mako.conf and register this Web redirect URI in Microsoft Entra: '+location.origin+'/ms-sso.lsp','hint'));
    if(snapshot.sso?.linked)sso.append(button('Unlink Microsoft account',()=>confirmPassword('Unlink Microsoft account',async password=>{await api('ssoUnlink',{password});closeDialog();await initialize();notice('Microsoft account unlinked. Sign in with your local password.');})));
    content.append(sso);
    const recovery=panel('Account recovery');recovery.append(el('p','If you lose access, the server operator can recover this account from the command line. Stop the portal first, then start Mako once with -reset-credentials username:password. Remove the option before restarting normal service. Recovery preserves the CA and device records.'));if(snapshot.role==='zone')recovery.replaceChildren(el('h2','Account recovery'),el('p','Ask the site administrator to reset your account password. A reset removes the linked Microsoft identity so you can link it again.'));content.append(recovery);
    const address=panel('Administration address');address.append(el('p',snapshot.adminOrigin),el('p','Select a configured zone address with working HTTPS. All browser sessions will be signed out. The old address remains available only if a zone still uses it.'));
    const options=[...new Set(list(snapshot.zones).filter(z=>z.tlsStatus?.status==='installed' && z.portalUrl!==snapshot.adminOrigin).map(z=>z.portalUrl))];
    if(options.length){const select=el('select');select.setAttribute('aria-label','New administration address');options.forEach(url=>{const option=el('option',url);option.value=url;select.append(option);});address.append(select,button('Change administration address',()=>confirmPassword('Change administration address',async password=>{const result=await api('adminAddress',{origin:select.value,password});location.assign(result.origin+'/');})));}
    else address.append(el('p','Add a zone address with working HTTPS before moving administration.','hint'));if(snapshot.role==='site')content.append(address);
  } else {

    const notifications=panel('Warnings and email');notifications.append(el('p',snapshot.notifications?.enabled?'Email delivery: '+snapshot.notifications.status:'Email delivery is disabled. Set sharkca.notifications=true and configure Mako SMTP to enable it.'));
    if(snapshot.role==='site' && snapshot.notifications?.enabled)notifications.append(button('Send test email',()=>confirmPassword('Send test email',async password=>{await api('notificationTest',{password});closeDialog();await refresh();notice('SMTP server accepted the notification batch.');})));
    notifications.append(table(['Time','Zone','Message','Device IP','WAN IP','Count','Email'],list(snapshot.alerts).map(a=>[date(a.last_seen),zoneName(a.zone_id),a.code,a.local_ip,a.peer,a.occurrences,a.delivery]),'No warnings recorded.'));content.append(notifications);

    const p=panel();p.append(el('p','Latest 200 stored events. The peer column records the observed caller; device entries also include the local device address.','hint'));

    p.append(table(['Time','Zone','Event','Administrator','Device / record','Device IP','Peer IP'],list(snapshot.audit).map(a=>[date(a.created),zoneName(a.zone_id),a.kind,a.actor,a.device_id,a.local_ip,a.peer]),'No activity recorded.'));content.append(p);

  }

}

function editUser(user){
  const body=dialog(user?'Reset zone administrator':'Add zone administrator'),form=el('form');
  const username=field(form,'Username','text',user?.username||'');username.required=true;username.readOnly=!!user;username.pattern='[A-Za-z0-9_.-]{1,64}';
  const label=el('label','Zone'),zone=el('select');zone.required=true;zone.setAttribute('aria-label','Zone');
  list(snapshot.zones).forEach(z=>{const o=el('option',z.name);o.value=z.id;zone.append(o);});if(user)zone.value=user.zoneId;label.append(zone);form.append(label);
  const password=field(form,'New account password','password');password.required=true;password.minLength=12;password.maxLength=128;password.autocomplete='new-password';
  const confirm=field(form,'Confirm your site administrator password','password');confirm.required=true;confirm.autocomplete='current-password';
  const submit=el('button','Save administrator','primary');submit.type='submit';form.append(submit);body.append(form);
  form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{await api('userSave',{username:username.value,zoneId:zone.value,newPassword:password.value,password:confirm.value});closeDialog();selectedZone=undefined;await initialize();notice('Administrator saved. Sign in again.');},submit);});
}

function editPolicy(zone){
  const body=dialog('Zone policy'),form=el('form'),name=field(form,'Zone name','text',zone.name);
  name.required=true;name.maxLength=64;
  const include=field(form,'Include device IP addresses','checkbox');include.checked=zone.includeIp;
  const ranges=field(form,'Allowed IPv4 CIDRs, separated by commas','text',list(zone.allowedRanges).join(', '));
  const password=field(form,'Confirm administrator password','password');password.required=true;password.autocomplete='current-password';
  const submit=el('button','Save policy','primary');submit.type='submit';form.append(submit);body.append(el('p','Policy changes apply to future issuance and registration refreshes. Existing certificates remain valid.'),form);
  form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{await api('zonePolicy',{id:zone.id,name:name.value,includeIp:include.checked,allowedRanges:include.checked?ranges.value.split(',').map(v=>v.trim()).filter(Boolean):[],password:password.value});closeDialog();await refresh();},submit);});
}

function confirmPassword(title,action) {
  const body=dialog(title),form=el('form'),password=field(form,'Confirm administrator password','password');password.required=true;password.autocomplete='current-password';password.maxLength=128;
  const submit=el('button','Confirm','primary');submit.type='submit';form.append(submit);body.append(form);
  form.addEventListener('submit',e=>{e.preventDefault();run(()=>action(password.value),submit);});
}

function caAction(action,title){return confirmPassword(title,async password=>{await api(action,{password});closeDialog();await refresh();notice('CA settings saved.');});}
async function caDownload(kind,fingerprint){const result=await api('caDownload',{kind,fingerprint}),url=URL.createObjectURL(new Blob([result.pem],{type:'application/x-pem-file'})),a=el('a');a.href=url;a.download=result.filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function importCa(){
  const body=dialog('Import signed intermediate'),form=el('form');
  body.append(el('p','Upload PEM files. Put the signed SharkCA certificate first, followed by any parent intermediates. Obtain the trust root separately from your CA and verify its fingerprint through a trusted channel. Import prepares the CA; it does not activate it.'));
  const chain=field(form,'Signed intermediate and parent chain','file');chain.accept='.pem,.cer,.crt';chain.required=true;
  const root=field(form,'Independently verified trust root','file');root.accept='.pem,.cer,.crt';root.required=true;
  const accepted=field(form,'I verified and approve this root as a trust anchor','checkbox');accepted.required=true;
  const password=field(form,'Confirm administrator password','password');password.required=true;password.autocomplete='current-password';
  const submit=el('button','Validate and prepare','primary');submit.type='submit';form.append(submit);body.append(form);
  form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{
    if(chain.files[0].size>60000||root.files[0].size>60000)throw Error('Each PEM file must be at most 60 KB.');
    await api('caImport',{chain:await chain.files[0].text(),root:await root.files[0].text(),trustAnchorApproved:accepted.checked,password:password.value});
    closeDialog();await refresh();notice('CA chain validated. Download its trust root and review the prepared CA before activation.');
  },submit);});
}

function createZone() { zoneWizard(); }

function zoneWizard(zone) {

  const body=dialog(zone?'Configure HTTPS · '+zone.name:'Create an enrollment zone'),form=el('form'),progress=el('p',undefined,'hint');form.noValidate=true;

  const steps=[el('section'),el('section'),el('section')];let step=0;

  const name=zone?null:field(steps[0],'Zone name');if(name){name.required=true;name.maxLength=64;}

  const initial=zone?.portalUrl ? new URL(zone.portalUrl) : snapshot.networkMode==='local' ? new URL(location.origin) : null;

  const host=field(steps[0],'Portal domain or IPv4 address','text',initial?.hostname||'');host.required=true;host.placeholder='ca.example.com or 192.168.1.20';

  const port=field(steps[0],'HTTPS port','number',initial?.port||'443');port.min=1;port.max=65535;port.required=true;

  steps[0].append(el('p','Enter only the domain or IP, without https:// or a path. It must reach Mako. Changing the address requires no registered devices; changing the certificate issuer does not.','hint'));

  const label=el('label','Portal certificate issuer'),issuer=el('select');

  for(const [value,title] of [['private','SharkCA (self-signed CA)'],['letsencrypt','Let’s Encrypt']]){const o=el('option',title);o.value=value;issuer.append(o);}

  issuer.value=zone?.tls?.issuer||(snapshot.networkMode==='wan'?'letsencrypt':'private');label.append(issuer);steps[1].append(label);

  steps[1].append(el('p',snapshot.networkMode==='wan'?'Let’s Encrypt is recommended for a VPS. Either option is available.':'Either option is available. Let’s Encrypt requires a public domain and Internet validation.','hint'));

  const privateInfo=el('div');privateInfo.append(el('p','Before connecting, import the SharkCA root into each device’s HTTP client trust store and the administrator’s browser trust store. Installing it on the PC alone does not configure the device.'),link('Download root PEM','/acme/root.pem'));

  const imported=field(privateInfo,'I will provision the CA root on clients before using this certificate','checkbox');

  const publicInfo=el('div'),email=field(publicInfo,'Let’s Encrypt contact email','email',zone?.tls?.email||'');

  publicInfo.append(el('p','Point public DNS at this server and allow HTTP-01 validation on external port 80, including renewals. For a LAN server, forward port 80 to Mako. The HTTPS port above does not change the validation port. The requested domain becomes public in certificate transparency logs.'));

  const terms=el('a','Read Let’s Encrypt terms');terms.href='https://letsencrypt.org/repository/';terms.target='_blank';terms.rel='noopener';publicInfo.append(terms);

  const accepted=field(publicInfo,'I accept the Let’s Encrypt terms and have configured HTTP validation','checkbox');accepted.checked=zone?.tls?.acceptTerms===true;

  steps[1].append(privateInfo,publicInfo);

  function issuerChanged(){const pub=issuer.value==='letsencrypt';privateInfo.hidden=pub;publicInfo.hidden=!pub;email.required=pub;accepted.required=pub;imported.required=!pub;}issuer.onchange=issuerChanged;issuerChanged();

  const review=el('p');steps[2].append(review);

  const shared=field(steps[2],'Apply these certificate settings to all zones using this hostname','checkbox');

  let ip,ranges;if(!zone){ip=field(steps[2],'Include device IP in certificates','checkbox');ranges=field(steps[2],'Allowed IPv4 CIDRs (separate with commas)','text','192.168.1.0/24');ip.onchange=()=>{ranges.required=ip.checked;};steps[2].append(el('p','Change the pre-filled range to match the device networks you want to allow. These settings affect device certificates. They do not change the portal HTTPS certificate.','hint'));}

  steps[2].append(el('p','The current HTTPS certificate stays active until its replacement is ready. Let’s Encrypt issuance runs in the background; refresh Zones to see its status.','hint'));

  const actions=el('div',undefined,'actions'),back=button('Back',()=>show(step-1)),next=button('Next',()=>{if(valid())show(step+1);},'primary'),submit=el('button',zone?'Save HTTPS settings':'Create zone','primary');submit.type='submit';actions.append(back,next,submit);form.append(progress,...steps,actions);body.append(form);

  function valid(){return [...steps[step].querySelectorAll('input')].filter(i=>!i.closest('[hidden]')).every(i=>i.reportValidity());}

  function show(n){step=n;steps.forEach((s,i)=>s.hidden=i!==step);progress.textContent='Step '+(step+1)+' of 3 · '+['Portal address','Certificate issuer','Review'][step];back.hidden=step===0;next.hidden=step===2;submit.hidden=step!==2;

    if(step===2){const siblings=list(snapshot.zones).filter(z=>z.id!==zone?.id&&z.portalUrl&&new URL(z.portalUrl).hostname===host.value.trim().toLowerCase());shared.parentElement.hidden=!siblings.length;shared.required=!!siblings.length;review.textContent=(name?.value||zone.name)+' · https://'+host.value.trim()+(Number(port.value)===443?'':':'+port.value)+' · '+issuer.selectedOptions[0].textContent+(siblings.length?' · Shared with '+siblings.map(z=>z.name).join(', '):'');}}

  form.addEventListener('submit',e=>{e.preventDefault();if(step!==2){if(valid())show(step+1);return;}if(!valid())return;run(async()=>{const tls={issuer:issuer.value};if(issuer.value==='letsencrypt')Object.assign(tls,{email:email.value.trim(),acceptTerms:accepted.checked});const data={host:host.value.trim(),port:Number(port.value),tls,updateShared:shared.checked};if(zone)data.id=zone.id;else Object.assign(data,{name:name.value.trim(),includeIp:ip.checked,allowedRanges:ip.checked?ranges.value.split(',').map(s=>s.trim()).filter(Boolean):[]});const result=await api(zone?'zoneUrl':'zoneCreate',data);closeDialog();await refresh();notice(result.warning||'Settings saved. Check the zone’s HTTPS status; the working certificate remains active during issuance.');},submit);});show(0);(name||host).focus();

}

function deleteDevice(device) {
  const body=dialog('Delete device · '+(device.label?device.label+'.local':'IP only'));
  body.append(el('p','Remove this registration and free its name? The device credential will stop working and unfinished certificate requests will be cancelled. Issued certificates and activity history remain. This does not revoke certificates or prevent fresh enrollment with the zone credentials.'));
  body.append(table(['Device IP','WAN / group'],[[device.local_ip,device.wan+' / '+device.group_id]],''));
  body.append(button('Cancel',closeDialog,'quiet'),button('Delete device',async()=>{await api('deviceDelete',{deviceId:device.id,acknowledge:true});closeDialog();await refresh();notice('Device registration deleted.');},'danger'));
}

async function deleteZone(zone) {

  const preview=await api('zoneDeletePreview',{id:zone.id}),body=dialog('Delete zone · '+zone.name);

  body.append(el('p','This deletes the zone, its enrollment credentials and all '+list(preview.devices).length+' listed registrations. Issued certificates and audit history remain. This does not revoke certificates.'));

  body.append(table(['Device','IP'],list(preview.devices).map(d=>[d.label?d.label+'.local':'IP only',d.local_ip]),'This zone has no registered devices.'));

  const acknowledge=field(body,'Delete this zone and its listed registrations','checkbox');

  body.append(button('Confirm deletion',async()=>{if(!acknowledge.checked)throw Error('Acknowledge deletion before continuing.');const result=await api('zoneDelete',{token:preview.token,acknowledge:true});closeDialog();await refresh();notice(result.warning||'Zone deleted. '+result.removed+' registration(s) removed.');},'danger'));

}

function showCredentials(zone,download=false) {

  const body=dialog('Credentials · '+zone.name),form=el('form'),password=field(form,'Confirm administrator password','password');password.required=true;password.autocomplete='current-password';

  const submit=el('button',download?'Download tokengen.c':'Reveal credentials','primary');submit.type='submit';form.append(submit);body.append(el('p',download?'The generated file contains this zone’s embedded enrollment identity. Keep it out of public source control.':'Treat these values as secrets. The display clears after one minute.'),form);

  form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{const value=await api(download?'zoneCode':'zoneSecret',{id:zone.id,password:password.value});password.value='';if(download){const url=URL.createObjectURL(value),a=el('a');a.href=url;a.download='tokengen.c';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);closeDialog();notice('Downloaded tokengen.c for '+zone.name+'.');return;}body.replaceChildren(el('p','Store these values securely. Do not include them in logs or source control.'));body.append(el('h3','Portal'),el('pre',value.portalUrl),el('h3','ACME directory'),el('pre',value.portalUrl+'/acme/directory'),el('h3','Zone key'),el('pre',value.zoneKey),el('h3','Secret'),el('pre',value.secret));secretTimer=setTimeout(closeDialog,60000);},submit);});password.focus();

}

function previewCleanup(zone) {

  const body=dialog('Clean inactive devices · '+zone.name),form=el('form'),days=field(form,'Inactive for at least (days)','number','90');days.min=1;days.max=3650;days.required=true;

  const submit=el('button','Preview devices','primary');submit.type='submit';form.append(submit);body.append(el('p','Preview up to 200 devices. Nothing is removed until you confirm the displayed list. Issued certificates and audit history are retained.'),form);

  form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{const preview=await api('cleanupPreview',{id:zone.id,days:Number(days.value)});body.replaceChildren(table(['Name','IP','Last seen'],list(preview.devices).map(d=>[d.label?d.label+'.local':'IP only',d.local_ip,date(d.last_seen)]),'No devices meet this inactivity threshold.'));if(!list(preview.devices).length)return;

    const acknowledge=field(body,'I understand this removes registrations, not issued certificates','checkbox');const remove=button('Remove listed devices',async()=>{if(!acknowledge.checked)throw Error('Acknowledge removal before continuing.');const result=await api('cleanupConfirm',{token:preview.token,acknowledge:true});closeDialog();await refresh();notice(result.removed+' device(s) removed; '+result.skipped+' skipped because they changed.');},'danger');body.append(el('p','This preview expires after five minutes. Devices that reconnect after the preview are skipped.','hint'),remove);

  },submit);});

}

async function initialize() {

  if(location.protocol==='http:') {

    const url=new URL(location.href);url.protocol='https:';url.port=document.body.dataset.httpsPort||'443';

    $('notice').replaceChildren(link('Open this page using HTTPS',url.href));$('notice').hidden=false;

    $('status').textContent='HTTPS required';$('breadcrumb').textContent='Administrator sign-in';return;

  }

  state=await api();const logged=state.authenticated;

  const publicView=view==='available' && !state.setup;
  $('accountName').textContent=logged?'Administrator':'Administrator sign-in';
  $('auth').hidden=logged||publicView;$('workspace').hidden=!logged&&!publicView;$('navigation').hidden=false;$('logout').hidden=!logged;
  document.querySelectorAll('[data-admin-nav]').forEach(node=>node.hidden=!logged);
  $('ssoLogin').hidden=logged||!state.sso;

  $('status').textContent=logged?(state.ready?'Issuer ready':'Issuer starting'):(state.setup?'Setup required':'Signed out');

  $('setupFields').hidden=!state.setup;$('confirmPassword').required=state.setup;$('networkMode').value=state.networkMode;

  $('password').autocomplete=state.setup?'new-password':'current-password';$('password').minLength=state.setup?12:1;

  $('authTitle').textContent=state.setup?'Set up your private CA':'Welcome back';$('authSubmit').textContent=state.setup?'Create administrator':'Sign in';

  $('authIntro').textContent=state.setup?'Choose a username and a password of at least 12 characters. Local mode creates a default local zone. WAN mode starts with no zones; add a device-facing domain or IP address after signing in.':'Sign in to manage your devices, zones and trust roots.';

  if(logged||publicView)await refresh();else $('breadcrumb').textContent=state.setup?'Portal setup':'Administrator sign-in';

}

$('authForm').addEventListener('submit',e=>{e.preventDefault();run(async()=>{if(state.setup && $('password').value!==$('confirmPassword').value)throw Error('Passwords do not match.');await api(state.setup?'setup':'login',{username:$('username').value,password:$('password').value,networkMode:$('networkMode').value});$('password').value='';$('confirmPassword').value='';await initialize();},$('authSubmit'));});

$('logout').addEventListener('click',()=>run(async()=>{closeDialog();await api('logout');snapshot=null;$('content').replaceChildren();await initialize();}));

$('refresh').addEventListener('click',()=>run(refresh,$('refresh')));

$('closeDialog').addEventListener('click',closeDialog);$('dialog').addEventListener('cancel',closeDialog);



run(initialize);

