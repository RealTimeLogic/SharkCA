-- Portal-only administration. SQL runs on the registry writer; password work
-- runs separately. Neither credentials nor browser sessions enter ACME messages.
local identity,http=appreq"identity",appreq"http"
local M={}
function M.create(config,db,startIssuer)
   local api={loaded=false}
   local sessions,settings,zones={},nil,{}
   local function user(username)
      if settings and settings.admin and settings.admin.username==username then return settings.admin end
      return settings and settings.users and settings.users[username]
   end
   local function putUser(saved,account,oldName)
      saved.users=saved.users or {}
      if account.zoneId then saved.users[oldName or account.username]=nil saved.users[account.username]=account
      else saved.admin=account end
   end
   local function hasSso()
      if settings.admin and settings.admin.sso then return true end
      for _,u in pairs(settings.users or {}) do if u.sso then return true end end
      return false
   end
   local worker=ba.thread.create()
   local key=ba.crypto.hash"sha256"(ba.tpm.uniquekey("SharkCA.admin.v1",32))(true,"binary")
   local function seal(value)
      local iv=ba.rndbs(12)
      local cipher,tag=ba.crypto.symmetric("GCM",key,iv):encrypt(ba.json.encode(value),"PKCS7")
      return ba.b64encode(iv..tag..cipher)
   end
   local function unseal(value)
      local raw=ba.b64decode(value)
      return assert(identity.decode(assert(ba.crypto.symmetric("GCM",key,raw:sub(1,12)):decrypt(raw:sub(29),raw:sub(13,28),"PKCS7"))))
   end
   local function passwordHash(password,salt)
      return ba.b64encode(ba.crypto.PBKDF2("sha256",password,salt,600000,32))
   end
   local function validUsername(value)
      return type(value)=="string" and #value>=1 and #value<=64 and not value:find("[^%w_.%-]")
   end
   local function audit(sql,kind,peer,id,ip,zoneId,actor)
      sql("INSERT INTO audit_events(kind,device_id,local_ip,peer,created,zone_id,actor) VALUES(?,?,?,?,?,?,?)",kind,id,ip,peer,os.time(),zoneId or zones[id] and id,actor)
   end
   local function newZone(name,includeIp,ranges,portalUrl)
      return {id=identity.random(),key=identity.random()..identity.random(),name=name,
         secret=identity.random()..identity.random(),includeIp=includeIp or false,allowedRanges=ranges or {},portalUrl=portalUrl}
   end
   local function saveZone(sql,zone)
      sql("INSERT INTO portal_zones(id,record) VALUES(?,?)",zone.id,seal(zone))
   end
   function api.initialize(callback)
      db.manage(function(sql)
         sql("CREATE TABLE IF NOT EXISTS portal_settings(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)")
         sql("CREATE TABLE IF NOT EXISTS portal_zones(id TEXT PRIMARY KEY,record TEXT NOT NULL)")
         local row=sql("SELECT record FROM portal_settings WHERE id=1")[1]
         local saved=row and unseal(row.record) or {}
         saved.users=saved.users or {}
         local loaded={}
         for _,z in ipairs(sql("SELECT record FROM portal_zones")) do
            local zone=unseal(z.record)
            loaded[zone.id]=zone
         end
         if not row then sql("INSERT INTO portal_settings VALUES(1,?)",seal(saved)) end
         return {settings=saved,zones=loaded}
      end,function(result,err)
         if not result then callback(nil,err) return end
         settings,zones=result.settings,result.zones
         local function activate()
            if settings.adminOrigin then config.setOrigin(settings.adminOrigin) end
            config.zones={}
            for _,zone in pairs(zones) do config.addZone(zone.key,zone) end
            config.configured=settings.admin~=nil or next(zones)~=nil
            api.loaded=true
            callback(true)
         end
         local supplied,raw,reset=false
         for i,arg in ipairs(mako and mako.argv or {}) do
            if arg=="-credentials" or arg=="-reset-credentials" then
               if supplied then callback(nil,"Specify only one credentials option.") return end
               supplied,raw,reset=true,mako.argv[i+1],arg=="-reset-credentials"
            end
         end
         if not supplied then activate() return end
         if settings.admin and not reset then activate() return end
         local sep=type(raw)=="string" and raw:find(":",1,true)
         local username=sep and raw:sub(1,sep-1)
         local password=sep and raw:sub(sep+1)
         raw=nil
         if not validUsername(username) or not password or #password<12 or #password>128 then
            callback(nil,"Invalid credentials option: use username:password, a 1-64 character username (letters, digits, _, . or -), and a 12-128 byte password.")
            return
         end
         if reset and not settings.admin then callback(nil,"Recovery requires an existing administrator. Use -credentials for installation.") return end
         if settings.users[username] then callback(nil,"This username belongs to a zone administrator.") return end
         worker:run(function()
            local salt=identity.random()
            local admin={username=username,salt=salt,hash=passwordHash(password,salt)}
            password=nil
            db.manage(function(sql)
               local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
               if reset or not saved.admin then
                  saved.admin=admin
                  sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
                  audit(sql,reset and "admin_credentials_recovered" or "admin_bootstrap","command-line")
               end
               return saved
            end,function(saved,e)
               if not saved then callback(nil,e) return end
               settings=saved activate()
            end)
         end)
      end)
   end
   local function newSession(peer,origin,authenticated,account)
      if authenticated and (not account or user(account.username)~=account or account.zoneId and not zones[account.zoneId]) then return end
      local now,count=os.time(),0
      for token,s in pairs(sessions) do
         if now>s.expires or now>s.deadline then sessions[token]=nil else count=count+1 end
      end
      if count>=128 then return end
      local token=identity.random()..identity.random()
      local session={csrf=identity.random(),peer=peer,origin=origin,authenticated=authenticated,user=authenticated and account,
         expires=now+1800,deadline=now+28800}
      sessions[token]=session
      return session,token
   end
   local attempts,pendingPasswords={},0
   local allow=http.limiter()
   local openid=require"loadconf".openid
   local sso
   if openid then
      local hasExpiry=openid.client_secret_expires~=nil
      assert(type(openid.redirect_uri)=="string" and openid.redirect_uri:match("^https://[^/]+/ms%-sso%.lsp$"),
         "openid.redirect_uri must be https://<portal-address>/ms-sso.lsp")
      sso=appreq"ms-sso".init(openid,{
         -- Protocol details may contain provider input. Persist only fixed codes.
         log=function() http.log("sso_validation_failed") end,
         notify=function(event)
            if not hasExpiry and event.kind~="credential-invalid" then return end
            local codes={['credential-expiring']="sso_credential_expiring",['credential-expired']="sso_credential_expired",
               ['credential-invalid']="sso_credential_invalid"}
            if codes[event.kind] then http.log(codes[event.kind]) end
         end
      })
   end
   local function getSession(request,peer,origin)
      local token=(request:header"Cookie" or ""):match("__Host%-sharkca=([0-9a-f]+)")
      local session=token and sessions[token]
      if session and (session.authenticated and (user(session.user.username)~=session.user or session.user.zoneId and not zones[session.user.zoneId]) or session.peer~=peer or session.origin~=origin or os.time()>session.expires or os.time()>session.deadline) then
         sessions[token]=nil session=nil
      end
      return session,token
   end
   -- The OIDC module verifies the identity. This adapter grants access only to
   -- the identity explicitly linked by the password-authenticated administrator.
   function api.sso(request,response)
      local origin="https://"..(request:header"Host" or ""):lower()
      local peer=identity.peer(request:peername())
      local session,token=getSession(request,peer,origin)
      local initiated=session and session.authenticated
      local function fail(message,status)
         http.log(initiated and "sso_signin_rejected" or "sso_request_rejected",nil,peer)
         local text=tostring(message):gsub("[&<>]",{['&']="&amp;",['<']="&lt;",['>']="&gt;"})
         http.send(response,status or 403,'<!doctype html><html lang="en"><head><meta charset="utf-8">'..
            '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Microsoft sign-in | SharkTrust Private CA</title>'..
            '<link rel="stylesheet" href="/assets/style.css"><link rel="stylesheet" href="/assets/portal.css"></head><body>'..
            '<main class="auth-card"><p class="eyebrow">SharkTrust Private CA</p><h1>Microsoft sign-in</h1><p>'..text..
            '</p><p><a href="/">Return to sign-in</a></p><p><a href="/account.lsp">Administrator settings</a></p></main></body></html>',
            {['Content-Type']="text/html; charset=utf-8"})
      end
      response:setheader("Cache-Control","no-store")
      response:setheader("Referrer-Policy","no-referrer")
      response:setheader("Content-Security-Policy","default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
      if request:method()~="GET" then return fail("Method not allowed",405) end
      if not sso or not api.loaded or not settings.admin or not request:issecure() or
         openid.redirect_uri~=origin.."/ms-sso.lsp" or not config.acceptOrigin(origin) then
         return fail("Microsoft sign-in is not configured for this portal address.")
      end
      if not allow(peer) then return fail("Too many requests. Try again in a minute.",429) end
      local basSession=request:session(true)
      if request:data"start" then
         local grant
         if request:data"link" then
            grant=session and session.ssoGrant
            if not grant or not session.authenticated or grant.expires<os.time() or
               not identity.equal(request:data"link",grant.nonce) then return fail("Confirm your password again to link an account.") end
            session.ssoGrant=nil
            grant={session=session,token=token}
         elseif not hasSso() then return fail("Link your Microsoft account after signing in with your password.") end
         basSession.sharkcaSso={settings=settings,peer=peer,origin=origin,link=grant,expires=os.time()+600}
         initiated=true
         local ok,err=sso.sendredirect(request)
         if not ok then basSession.sharkcaSso=nil return fail(err,503) end
         return
      end
      local flow=basSession.sharkcaSso
      basSession.sharkcaSso=nil
      -- Only server-held flow state establishes a sign-in attempt. Query fields
      -- on an unsolicited callback must not turn a probe into an email alert.
      initiated=initiated or flow and flow.peer==peer and flow.origin==origin
      if not flow or flow.settings~=settings or flow.peer~=peer or flow.origin~=origin or flow.expires<os.time() then
         return fail("Sign-in expired or the administrator changed. Start again.")
      end
      local header,claims=sso.login(request)
      if not header then return fail(claims or "Microsoft sign-in failed.") end
      local linked={tenant=claims.tid,oid=claims.oid}
      local function validFlow()
         local link=flow.link
         return api.loaded and settings==flow.settings and flow.expires>=os.time() and
            (not link or sessions[link.token]==link.session and link.session.expires>=os.time() and link.session.deadline>=os.time())
      end
      if not validFlow() then return fail("Administrator session changed. Start again.") end
      local account=flow.link and flow.link.session.user
      local matching
      local function match(a)
         if a.sso and a.sso.tenant==linked.tenant and a.sso.oid==linked.oid then matching=a end
      end
      match(settings.admin) for _,a in pairs(settings.users or {}) do match(a) end
      if flow.link then
         if matching and matching~=account then return fail("This Microsoft account is already linked to another administrator.") end
      else account=matching end
      if not account or account.zoneId and not zones[account.zoneId] then return fail("This Microsoft account is not linked to an administrator.") end
      local deferred=response:deferred()
      request,response=nil,nil
      db.manage(function(sql)
         if not validFlow() then return {error="Administrator session changed. Start again."} end
         if flow.link then
            local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
            local updated={} for k,v in pairs(account) do updated[k]=v end updated.sso=linked
            putUser(saved,updated)
            sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
            audit(sql,"admin_sso_linked",peer,nil,nil,account.zoneId,account.username)
            return {settings=saved}
         end
         audit(sql,"admin_sso_login",peer,nil,nil,account.zoneId,account.username)
         return {}
      end,function(result,err)
         if not result or result.error then return http.send(deferred,403,{error=result and result.error or "Storage unavailable"},nil,true) end
         if not validFlow() then return http.send(deferred,403,{error="Administrator session changed. Start again."},nil,true) end
         if result.settings then settings=result.settings sessions={} end
         local session,token=newSession(peer,origin,true,user(account.username))
         if not session then return http.send(deferred,503,{error="Session limit reached."},nil,true) end
         http.send(deferred,303,"",{Location="/account.lsp",
            ['Set-Cookie']="__Host-sharkca="..token.."; Path=/; Secure; HttpOnly; SameSite=Strict"},true)
      end)
   end
   function api.handle(request,response)
      local peer=identity.peer(request:peername())
      local method=request:method()
      local host=(request:header"Host" or ""):lower()
      local origin="https://"..host
      local validHost=host:match("^[%w%.%-]+$") or host:match("^[%w%.%-]+:%d+$")
      local port=host:match(":(%d+)$")
      validHost=validHost and (not port or tonumber(port)>0 and tonumber(port)<=65535)
      local loopback=peer=="127.0.0.1" or peer=="::1"
      local setupHost=host:match("^localhost:?") or host:match("^127%.0%.0%.1:?")
      setupHost=setupHost and (host:match("^localhost$") or host:match("^localhost:%d+$") or host:match("^127%.0%.0%.1$") or host:match("^127%.0%.0%.1:%d+$"))
      local function fail(code,status) return http.send(response,status or 400,{error=code}) end
      if not request:issecure() then return fail("Open this page using HTTPS.",400) end
      if not api.loaded then return fail("Portal storage is not ready. Check the Mako startup log.",503) end
      if not validHost or not identity.origin(origin) or settings.adminOrigin and not config.acceptOrigin(origin) then return fail("Use a configured portal address.",403) end
      if not settings.admin and (not loopback or not setupHost) then return fail("First-time setup must be opened on localhost at the portal computer.",403) end
      if not allow(peer) then return fail("Too many requests. Try again in a minute.",429) end
      local session,token=getSession(request,peer,origin)
      local headers={}
      local function cookie(value)
         headers["Set-Cookie"]="__Host-sharkca="..value.."; Path=/; Secure; HttpOnly; SameSite=Strict"
      end
      if method=="GET" then
         if not session then session,token=newSession(peer,origin,false) if not session then return fail("Session limit reached.",503) end cookie(token) end
         session.expires=os.time()+1800
         return http.send(response,200,{setup=not settings.admin,authenticated=session.authenticated or false,
            sso=sso and hasSso() and openid.redirect_uri==origin.."/ms-sso.lsp" or false,
            csrf=session.csrf,ready=app.ready or false,networkMode=config.networkMode,origin=origin},headers)
      end
      if method~="POST" then return fail("Method not allowed",405) end
      if request:header"Origin"~=origin or not session or not identity.equal(request:header"X-CSRF-Token",session.csrf) then return fail("Reload this page before trying again.",403) end
      if (request:header"Content-Type" or ""):match("^([^;]+)")~="application/json" then return fail("JSON required",415) end
      local data,err=http.read(request,131072)
      if not data then return fail(err) end
      local action=data.action
      if type(action)~="string" then return fail("Operation required.") end
      if action~="setup" and action~="login" and action~="available" and not session.authenticated then return fail("Sign in to continue.",401) end
      session.expires=os.time()+1800
      local deferred=response:deferred()
      request,response=nil,nil
      local function reply(result,problem,status)
         http.send(deferred,problem and (status or 400) or 200,problem and {error=problem} or result,headers,true)
      end
      local function complete(result,problem)
         if not result then return reply(nil,problem or "Storage unavailable",503) end
         if result.error then return reply(nil,result.error) end
         reply(result)
      end
      local authorizedSettings=settings
      local account=session.user
      local zoneId=account and account.zoneId
      local function ownZone(id) return zones[id] and (not zoneId or zoneId==id) end
      local function protectsPortal(zone)
         if not zoneId or not zone.portalUrl or not config.adminOrigin or
            zone.portalUrl:match("^https://([^:]+)")~=config.adminOrigin:match("^https://([^:]+)") then return false end
         return zone.tls and zone.tls.issuer=="letsencrypt"
      end
      if session.authenticated then
         if zoneId then
            local sharedActions={logout=true,credentials=true,ssoLink=true,ssoUnlink=true,dashboard=true,available=true,
               zoneUrl=true,zonePolicy=true,zoneSecret=true,zoneCode=true,zoneDeletePreview=true,zoneDelete=true,
               cleanupPreview=true,cleanupConfirm=true,deviceDelete=true,caPrepare=true,caRotate=true,caImport=true,
               caActivate=true,caDiscard=true,caCsr=true,caDownload=true}
            if not sharedActions[action] then return reply(nil,"Site administrator required.",403) end
         end
         if action:match("^ca") then
            if zoneId and data.zoneId~=zoneId or data.zoneId and not ownZone(data.zoneId) then return reply(nil,"Zone access denied.",403) end
         elseif zoneId and data.id and not ownZone(data.id) then
            return reply(nil,"Zone access denied.",403)
         end
      end
      -- Recheck queued operations after credential changes or sign-out.
      local function manage(operation,callback)
         db.manage(function(sql)
            if sessions[token]~=session or settings~=authorizedSettings then
               return {error="Session changed. Sign in again."}
            end
            return operation(sql)
         end,callback)
      end
      local function installed(result,problem,createdZone)
         if not result or result.error then return complete(result,problem) end
         local function refreshListener()
         app.listener.refresh(function(ok,e)
            if not ok then result.warning="Zone saved, but HTTPS certificate installation failed: "..tostring(e) end
            complete(result)
         end)
         end
         if createdZone then app.issuer.ensure(createdZone.id,function(ok,e)
            if not ok then result.warning="Zone saved; CA initialization failed." end
            refreshListener()
         end) else refreshListener() end
      end
      local function authorize(callback,creating)
         if creating and not validUsername(data.username) then return reply(nil,"Use a username with 1 to 64 letters, digits, _, . or -.") end
         if type(data.password)~="string" or #data.password>128 or #data.password<(creating and 12 or 1) then return reply(nil,"Use a password with 12 to 128 bytes.") end
         local now=os.time()
         local bucket=attempts[peer]
         if not bucket or now-bucket.time>=60 then bucket={time=now,count=0} attempts[peer]=bucket end
         if bucket.count>=5 then return reply(nil,"Too many password attempts. Try again in a minute.",429) end
         if pendingPasswords>=8 then return reply(nil,"Password service is busy. Try again shortly.",429) end
         -- Bound the peer map as well as work queued on the password thread.
         for p,b in pairs(attempts) do if now-b.time>=60 then attempts[p]=nil end end
         bucket.count=bucket.count+1
         pendingPasswords=pendingPasswords+1
         worker:run(function()
            pendingPasswords=pendingPasswords-1
            if not api.loaded then return reply(nil,"Portal is stopping.",503) end
            local current=action=="login" and user(data.username) or account or settings.admin
            local salt=creating and identity.random() or current and current.salt
            if not salt then salt=settings.admin and settings.admin.salt or identity.random() end
            local hash=passwordHash(data.password,salt)
            data.password=nil
            if not api.loaded or not creating and user(current and current.username)~=current or not creating and action~="login" and sessions[token]~=session then
               return reply(nil,"Credentials changed. Sign in again.",401)
            end
            local validPassword=creating or current and identity.equal(hash,current.hash)
            local validUser=action~="login" or current and identity.equal(data.username,current.username)
            if not validPassword or not validUser then return reply(nil,action=="login" and "Incorrect username or password." or "Incorrect password.",401) end
            callback(creating and {username=data.username,salt=salt,hash=hash} or current)
         end)
      end
      local function signedIn(current)
         local s,t=newSession(peer,origin,true,current or settings.admin)
         if not s then return reply(nil,"Session limit reached.",503) end
         sessions[token]=nil cookie(t)
         db.manage(function(sql)
            audit(sql,"admin_login",peer,nil,nil,s.user.zoneId,s.user.username)
            return true
         end,function() end)
         reply({ok=true,csrf=s.csrf})
      end
      if action=="setup" then
         if settings.admin then return reply(nil,"Setup is already complete.",409) end
         if data.networkMode~="local" and data.networkMode~="wan" then return reply(nil,"Choose a network mode.") end
         return authorize(function(admin)
            manage(function(sql)
               local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
               if saved.admin then return {error="Setup is already complete."} end
               if data.networkMode~=config.networkMode and tonumber(sql("SELECT count(*) AS n FROM devices")[1].n)>0 then
                  return {error="Existing devices prevent changing network mode."}
               end
               saved.admin,saved.adminOrigin=admin,saved.adminOrigin or origin
               local zone
               if data.networkMode=="local" and not next(zones) then zone=newZone("Default zone",false,{},origin) saveZone(sql,zone) end
               sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
               sql("UPDATE schema_version SET network_mode=?",data.networkMode)
               audit(sql,"admin_setup",peer)
               return {settings=saved,zone=zone}
            end,function(result,e)
               if not result or result.error then return complete(result,e) end
               settings=result.settings config.networkMode=data.networkMode config.setOrigin(settings.adminOrigin)
               config.configured=true
               if result.zone then zones[result.zone.id]=result.zone config.addZone(result.zone.key,result.zone) end
               startIssuer() signedIn()
            end)
         end,true)
      elseif action=="login" then
         if not settings.admin then return reply(nil,"Setup is required.",409) end
         return authorize(function(current)
            if settings.adminOrigin then signedIn(current) return end
            -- Headless bootstrap: only a successful login may bind the first address.
            manage(function(sql)
               local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
               if saved.adminOrigin and saved.adminOrigin~=origin then return {error="Use the configured portal address."} end
               saved.adminOrigin=origin
               local zone
               if config.networkMode=="local" and not next(zones) then zone=newZone("Default zone",false,{},origin) saveZone(sql,zone) end
               sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
               audit(sql,"admin_address_configured",peer)
               return {settings=saved,zone=zone}
            end,function(result,e)
               if not result or result.error then return complete(result,e) end
               settings=result.settings config.setOrigin(settings.adminOrigin)
               if result.zone then zones[result.zone.id]=result.zone config.addZone(result.zone.key,result.zone) end
               if result.zone then app.issuer.ensure(result.zone.id,function() app.listener.refresh() signedIn() end)
               else app.listener.refresh() signedIn() end
            end)
         end)
      elseif action=="logout" then
         sessions[token]=nil headers["Set-Cookie"]="__Host-sharkca=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
         return reply({ok=true})
      elseif action=="credentials" then
         if not validUsername(data.username) then return reply(nil,"Use a username with 1 to 64 letters, digits, _, . or -.") end
         if type(data.newPassword)~="string" or #data.newPassword<12 or #data.newPassword>128 then
            return reply(nil,"Use a new password with 12 to 128 bytes.")
         end
         return authorize(function()
            local current=account
            if user(data.username) and user(data.username)~=current then return reply(nil,"Username is already in use.") end
            local salt=identity.random()
            local admin={username=data.username,salt=salt,hash=passwordHash(data.newPassword,salt),sso=current.sso,zoneId=current.zoneId}
            data.newPassword=nil
            manage(function(sql)
               local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
               if user(current.username)~=current or user(data.username) and user(data.username)~=current or sessions[token]~=session then
                  return {error="Credentials changed. Sign in again."}
               end
               putUser(saved,admin,current.username)
               sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
               audit(sql,"admin_credentials_changed",peer,nil,nil,zoneId,account.username)
               return saved
            end,function(saved,e)
               if not saved or saved.error then return complete(saved,e) end
               settings=saved sessions={}
               headers["Set-Cookie"]="__Host-sharkca=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
               reply({ok=true})
            end)
         end)
      elseif action=="ssoLink" then
         if not sso or openid.redirect_uri~=origin.."/ms-sso.lsp" then return reply(nil,"Configure Microsoft sign-in for this portal address first.") end
         return authorize(function()
            local nonce=identity.random()
            session.ssoGrant={nonce=nonce,expires=os.time()+120}
            reply({url="/ms-sso.lsp?start=1&link="..nonce})
         end)
      elseif action=="ssoUnlink" then
         return authorize(function()
            manage(function(sql)
               local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
               local updated={} for k,v in pairs(account) do updated[k]=v end updated.sso=nil
               putUser(saved,updated)
               sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
               audit(sql,"admin_sso_unlinked",peer,nil,nil,zoneId,account.username)
               return saved
            end,function(saved,err)
               if not saved or saved.error then return complete(saved,err) end
               settings=saved sessions={}
               reply({ok=true})
            end)
         end)
      elseif action=="adminAddress" then
         local target=type(data.origin)=="string" and identity.origin(data.origin)
         local configured=false
         for _,zone in pairs(zones) do if zone.portalUrl==target then configured=true end end
         if not target or not configured or app.listener.zoneStatus(target).status~="installed" then
            return reply(nil,"Choose a zone address with an installed HTTPS certificate.")
         end
         return authorize(function()
            manage(function(sql)
               local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
               saved.adminOrigin=target
               sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
               audit(sql,"admin_address_changed",peer)
               return saved
            end,function(saved,e)
               if not saved or saved.error then return complete(saved,e) end
               settings=saved config.setOrigin(target) sessions={}
               headers["Set-Cookie"]="__Host-sharkca=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
               app.listener.refresh()
               reply({ok=true,origin=target})
            end)
         end)
      elseif action=="userSave" or action=="userDelete" then
         if not validUsername(data.username) or data.username==settings.admin.username then return reply(nil,"Choose a zone administrator username.") end
         if action=="userSave" and (not zones[data.zoneId] or type(data.newPassword)~="string" or #data.newPassword<12 or #data.newPassword>128) then
            return reply(nil,"Choose a zone and a 12 to 128 byte password.")
         end
         return authorize(function()
            local updated
            if action=="userSave" then
               local salt=identity.random()
               updated={username=data.username,zoneId=data.zoneId,salt=salt,hash=passwordHash(data.newPassword,salt)}
               data.newPassword=nil
            end
            manage(function(sql)
               local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
               saved.users=saved.users or {}
               local count=0 for _ in pairs(saved.users) do count=count+1 end
               if updated and not zones[updated.zoneId] then return {error="Zone no longer exists."} end
               if updated and not saved.users[data.username] and count>=256 then return {error="Administrator limit reached."} end
               local previous=saved.users[data.username]
               if not updated and not previous then return {error="Administrator not found."} end
               saved.users[data.username]=updated
               sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
               audit(sql,updated and "zone_admin_saved" or "zone_admin_deleted",peer,data.username,nil,
                  updated and updated.zoneId or previous.zoneId,account.username)
               return saved
            end,function(saved,e)
               if not saved or saved.error then return complete(saved,e) end
               settings=saved sessions={}
               reply({ok=true})
            end)
         end)
      elseif action=="available" then
         return manage(function(sql)
            local devices={}
            for key,zone in pairs(config.zones) do
               if zone.portalUrl==origin and (not zoneId or zoneId==zone.id) then
                  local rows=sql([[SELECT d.label,d.local_ip FROM devices d JOIN network_groups g ON d.group_id=g.id
                     WHERE d.zone_key=? AND g.conflicted=0 AND ]]..
                     (config.networkMode=="local" and "g.id=?" or "g.wan=?").." ORDER BY d.label,d.local_ip LIMIT "..(200-#devices),
                     key,config.networkMode=="local" and "local" or peer)
                  for _,d in ipairs(rows) do
                     devices[#devices+1]={name=d.label and d.label..".local" or d.local_ip,ip=d.local_ip}
                  end
               end
               if #devices==200 then break end
            end
            table.sort(devices,function(a,b) return a.name<b.name end)
            return {devices=devices}
         end,complete)
      elseif action=="dashboard" then
         return manage(function(sql)
            local publicZones,authorities,users={},{},{}
            local selected=data.zoneId
            if selected and not ownZone(selected) then return {error="Zone access denied."} end
            if zoneId then selected=zoneId end
            for id,zone in pairs(zones) do
               if not zoneId or zoneId==id then
                  publicZones[#publicZones+1]={id=id,name=zone.name,includeIp=zone.includeIp,portalUrl=zone.portalUrl,
                     tls=zone.tls or {issuer="private"},tlsStatus=app.listener.zoneStatus(zone.portalUrl),allowedRanges=zone.allowedRanges,
                     devices=tonumber(sql("SELECT count(*) AS n FROM devices WHERE zone_key=?",zone.key)[1].n)}
               end
            end
            table.sort(publicZones,function(a,b) return a.name<b.name end)
            local filter=zoneId or selected
            local where=filter and " WHERE zone_id=?" or ""
            local function scoped(query,suffix)
               if filter then return sql(query..where..(suffix or ""),filter) end
               return sql(query..(suffix or ""))
            end
            local deviceSql=[[SELECT d.id,d.label,d.local_ip,d.last_peer,d.last_seen,d.group_id,g.wan,g.conflicted
               FROM devices d JOIN network_groups g ON d.group_id=g.id]]
            local devices=filter and sql(deviceSql.." WHERE d.zone_key=? ORDER BY d.last_seen DESC LIMIT 200",zones[filter].key) or sql(deviceSql.." ORDER BY d.last_seen DESC LIMIT 200")
            for _,z in ipairs(publicZones) do
               local row=sql("SELECT record FROM authorities WHERE service=?",z.id)[1]
               if row and row.record then local ca=ba.json.decode(row.record)
                  authorities[#authorities+1]={zoneId=z.id,name=z.name,expiresAt=ca.expiresAt,curve=ca.descriptor.curve}
               end
            end
            if not zoneId then for _,u in pairs(settings.users or {}) do users[#users+1]={username=u.username,zoneId=u.zoneId,linked=u.sso~=nil} end end
            local deviceCount=filter and tonumber(sql("SELECT count(*) AS n FROM devices WHERE zone_key=?",zones[filter].key)[1].n) or tonumber(sql("SELECT count(*) AS n FROM devices")[1].n)
            return {username=account.username,role=zoneId and "zone" or "site",zoneId=zoneId,users=users,
               sso={configured=sso~=nil,linked=account.sso~=nil,addressReady=sso and openid.redirect_uri==origin.."/ms-sso.lsp" or false},
               lifecycle=app.lifecycle.snapshot(sql,selected or "portal"),selectedZone=selected,
               adminOrigin=not zoneId and settings.adminOrigin or nil,zones=publicZones,devices=devices,authorities=authorities,ready=app.ready or false,origin=origin,
               networkMode=config.networkMode,listener={status=app.listener.status},deviceCount=deviceCount,
               certificateCount=tonumber(scoped("SELECT count(*) AS n FROM certificates")[1].n),
               certificates=scoped("SELECT id,serial,directory,fingerprint,not_after,zone_id,(SELECT identifiers FROM orders WHERE orders.id=certificates.id) AS identifiers FROM certificates"," ORDER BY rowid DESC LIMIT 200"),
               notifications=not zoneId and {enabled=app.alerts.enabled,status=app.alerts.status} or nil,
               alerts=scoped("SELECT code,local_ip,peer,last_seen,occurrences,delivery,zone_id FROM portal_alerts"," ORDER BY id DESC LIMIT 200"),
               audit=scoped("SELECT kind,device_id,local_ip,peer,created,zone_id,actor FROM audit_events"," ORDER BY id DESC LIMIT 200")}
         end,complete)
      elseif action=="caPrepare" or action=="caRotate" or action=="caImport" or action=="caActivate" or action=="caDiscard" or action=="caCsr" or action=="caDownload" then
         local function execute()
            app.lifecycle.action(action,data,function()
               return api.loaded and settings==authorizedSettings and sessions[token]==session and
                  (not data.zoneId or ownZone(data.zoneId)) and
                  os.time()<=session.expires and os.time()<=session.deadline
            end,peer,function(result,err) reply(result,err) end)
         end
         if action=="caDownload" then return execute() end
         return authorize(execute)
      elseif action=="notificationTest" then
         return authorize(function()
            app.alerts.record("notification_test",nil,peer)
            app.alerts.send(function(ok,e) reply(ok and {ok=true},e,503) end)
         end)
      elseif action=="zonePolicy" then
         local zone=zones[data.id]
         if not zone then return reply(nil,"Zone not found.",404) end
         if type(data.name)~="string" or #data.name<1 or #data.name>64 or data.name:find("%c") or
            type(data.includeIp)~="boolean" or type(data.allowedRanges)~="table" or #data.allowedRanges>32 or
            data.includeIp and #data.allowedRanges==0 then return reply(nil,"Enter a zone name and valid certificate policy.") end
         for _,range in ipairs(data.allowedRanges) do if not identity.range(range) then return reply(nil,"Use canonical IPv4 CIDRs.") end end
         local updated={} for k,v in pairs(zone) do updated[k]=v end
         updated.name,updated.includeIp,updated.allowedRanges=data.name,data.includeIp,data.allowedRanges
         return authorize(function()
            manage(function(sql)
               if not ownZone(zone.id) then return {error="Zone no longer exists."} end
               sql("UPDATE portal_zones SET record=? WHERE id=?",seal(updated),zone.id)
               sql("UPDATE orders SET status='invalid' WHERE zone_id=? AND status IN ('ready','processing')",zone.id)
               audit(sql,"zone_policy_changed",peer,zone.id,nil,zone.id,account.username)
               return {ok=true}
            end,function(result,e)
               if result and not result.error then zones[zone.id]=updated config.addZone(updated.key,updated) end
               complete(result,e)
            end)
         end)
      elseif action=="zoneCreate" or action=="zoneUrl" then
         local port=data.port or 443
         if type(data.host)~="string" or data.host:find("[:/%s]") or type(port)~="number" or port%1~=0 or port<1 or port>65535 then
            return reply(nil,"Enter a domain name or IPv4 address and a valid HTTPS port.")
         end
         local portalUrl,localOnly=identity.origin("https://"..data.host..":"..port)
         if not portalUrl then return reply(nil,"Enter a domain name or IPv4 address without a URL prefix or path.") end
         if config.networkMode=="wan" and localOnly then return reply(nil,"WAN zones require a device-reachable hostname or address, not localhost or loopback.") end
         local host=portalUrl:match("^https://([^:]+)")
         local tls=data.tls or {issuer="private"}
         if type(tls)~="table" or tls.issuer~="private" and tls.issuer~="letsencrypt" then return reply(nil,"Choose a portal certificate issuer.") end
         if tls.issuer=="letsencrypt" then
            if localOnly or identity.ip(host) or not host:find("%.") or host:match("%.local$") then
               return reply(nil,"Let's Encrypt requires a public domain name. Use SharkCA for local names or IP addresses.")
            end
            if type(tls.email)~="string" or #tls.email>254 or not tls.email:match("^[^%s@]+@[^%s@]+%.[^%s@]+$") then return reply(nil,"Enter a contact email for Let's Encrypt.") end
            if tls.acceptTerms~=true then return reply(nil,"Accept the Let's Encrypt terms before requesting a certificate.") end
            tls={issuer="letsencrypt",email=tls.email,acceptTerms=true}
         else tls={issuer="private"} end
         local function shared(sql,id)
            local changes={}
            for otherId,other in pairs(zones) do
               if otherId~=id and other.portalUrl and other.portalUrl:match("^https://([^:]+)")==host then
                  local old=other.tls or {issuer="private"}
                  if old.issuer~=tls.issuer or old.email~=tls.email then
                     if zoneId then return nil,"A site administrator must change HTTPS settings shared with another zone." end
                     if data.updateShared~=true then return nil,"This hostname is shared. Confirm updating its certificate settings for all zones." end
                     local updated={} for k,v in pairs(other) do updated[k]=v end updated.tls=tls
                     changes[#changes+1]=updated
                  end
               end
            end
            -- Validate the entire request before making any writes.
            return changes
         end
         local function saveShared(sql,changes)
            for _,z in ipairs(changes) do sql("UPDATE portal_zones SET record=? WHERE id=?",seal(z),z.id) end
         end
         local function changed(result)
            for _,z in ipairs(result.shared or {}) do zones[z.id]=z config.addZone(z.key,z) end
            result.shared=nil
         end
         if zoneId and config.adminOrigin and host==config.adminOrigin:match("^https://([^:]+)") then
            local old=zones[zoneId].tls or {issuer="private"}
            if old.issuer~=tls.issuer or old.email~=tls.email then return reply(nil,"A site administrator must change the administration hostname's HTTPS settings.",403) end
         end
         if action=="zoneUrl" then
            local zone=zones[data.id]
            if not zone then return reply(nil,"Zone not found.",404) end
            if protectsPortal(zone) and portalUrl~=zone.portalUrl then return reply(nil,"A site administrator must move the zone that supplies portal HTTPS.",403) end
            local updated={} for k,v in pairs(zone) do updated[k]=v end updated.portalUrl,updated.tls=portalUrl,tls
            return manage(function(sql)
               if not zones[zone.id] then return {error="Zone no longer exists."} end
               if portalUrl~=zone.portalUrl and tonumber(sql("SELECT count(*) AS n FROM devices WHERE zone_key=?",zone.key)[1].n)>0 then
                  return {error="Remove this zone's device registrations before changing its portal URL."}
               end
               local changes,e=shared(sql,zone.id) if not changes then return {error=e} end
               saveShared(sql,changes)
               sql("UPDATE portal_zones SET record=? WHERE id=?",seal(updated),zone.id)
               audit(sql,"zone_https_changed",peer,zone.id) return {ok=true,shared=changes}
            end,function(result,e)
               if result and not result.error then changed(result) zones[zone.id]=updated config.addZone(updated.key,updated) end
               installed(result,e)
            end)
         end
         if type(data.name)~="string" or #data.name<1 or #data.name>64 or data.name:find("%c") then return reply(nil,"Zone name must be 1 to 64 characters.") end
         if type(data.includeIp)~="boolean" or type(data.allowedRanges)~="table" or #data.allowedRanges>32 then return reply(nil,"Invalid zone policy.") end
         if data.includeIp and #data.allowedRanges==0 then return reply(nil,"IP certificates require at least one allowed IPv4 CIDR.") end
         for _,range in ipairs(data.allowedRanges) do if not identity.range(range) then return reply(nil,"Use canonical IPv4 CIDRs, for example 192.168.1.0/24.") end end
         local zone=newZone(data.name,data.includeIp,data.allowedRanges,portalUrl)
         zone.tls=tls
         return manage(function(sql)
            if tonumber(sql("SELECT count(*) AS n FROM portal_zones")[1].n)>=128 then return {error="Zone limit reached."} end
            local changes,e=shared(sql) if not changes then return {error=e} end
            saveShared(sql,changes)
            saveZone(sql,zone) audit(sql,"zone_created",peer,zone.id,nil,zone.id,account.username)
            return {ok=true,shared=changes}
         end,function(result,e)
            if result and not result.error then changed(result) zones[zone.id]=zone config.addZone(zone.key,zone) end
            installed(result,e,zone)
         end)
      elseif action=="zoneSecret" or action=="zoneCode" then
         local zone=zones[data.id]
         if not zone then return reply(nil,"Zone not found.",404) end
         if not zone.portalUrl then return reply(nil,"Set the zone's device-facing HTTPS URL first.") end
         return authorize(function()
            manage(function(sql)
               if not zones[zone.id] then return {error="Zone no longer exists."} end
               audit(sql,action=="zoneCode" and "zone_code_downloaded" or "zone_credentials_viewed",peer,zone.id)
               return {zoneKey=zone.key,secret=zone.secret,portalUrl=zones[zone.id].portalUrl}
            end,function(result,e)
               if sessions[token]~=session then return reply(nil,"Sign in to continue.",401) end
               if not result or result.error or action=="zoneSecret" then return complete(result,e) end
               headers["Content-Type"]="text/plain; charset=utf-8"
               headers["Content-Disposition"]='attachment; filename="tokengen.c"'
               headers["X-Content-Type-Options"]="nosniff"
               http.send(deferred,200,appreq"tokengen"(result),headers,true)
            end)
         end)
      elseif action=="zoneDeletePreview" then
         local zone=zones[data.id]
         if not zone then return reply(nil,"Zone not found.",404) end
         if protectsPortal(zone) then return reply(nil,"A site administrator must delete the zone that supplies portal HTTPS.",403) end
         return manage(function(sql)
            return {devices=sql("SELECT id,label,local_ip FROM devices WHERE zone_key=? ORDER BY id",zone.key)}
         end,function(result,e)
            if not result then return complete(result,e) end
            session.zoneDeletion={id=zone.id,token=identity.random(),expires=os.time()+300,devices=result.devices}
            result.token=session.zoneDeletion.token reply(result)
         end)
      elseif action=="zoneDelete" then
         local preview=session.zoneDeletion
         if not preview or preview.expires<os.time() or not identity.equal(preview.token,data.token) or data.acknowledge~=true then
            return reply(nil,"Preview this zone and acknowledge its deletion first.")
         end
         session.zoneDeletion=nil
         local zone=zones[preview.id]
         if not zone then return reply(nil,"Zone not found.",404) end
         return manage(function(sql)
            if not zones[zone.id] then return {error="Zone no longer exists."} end
            if protectsPortal(zones[zone.id]) then return {error="A site administrator must delete the zone that supplies portal HTTPS."} end
            local current=sql("SELECT id,local_ip FROM devices WHERE zone_key=? ORDER BY id",zone.key)
            if #current~=#preview.devices then return {error="Zone membership changed. Create a fresh deletion preview."} end
            for i,d in ipairs(current) do if d.id~=preview.devices[i].id then return {error="Zone membership changed. Create a fresh deletion preview."} end end
            for _,d in ipairs(current) do
               sql("UPDATE orders SET status='invalid' WHERE device_id=? AND status IN ('ready','processing')",d.id)
               audit(sql,"zone_device_removed",peer,d.id,d.local_ip,zone.id,account.username)
            end
            sql("DELETE FROM devices WHERE zone_key=?",zone.key)
            sql("DELETE FROM portal_zones WHERE id=?",zone.id)
            for username,u in pairs(settings.users or {}) do
               if u.zoneId==zone.id then
                  local saved=unseal(sql("SELECT record FROM portal_settings WHERE id=1")[1].record)
                  saved.users[username]=nil sql("UPDATE portal_settings SET record=? WHERE id=1",seal(saved))
               end
            end
            sql("UPDATE orders SET status='invalid' WHERE zone_id=? AND status IN ('ready','processing')",zone.id)
            audit(sql,"zone_deleted",peer,zone.id,nil,zone.id,account.username)
            return {removed=#current}
         end,function(result,e)
            if result and not result.error then
               zones[zone.id]=nil config.zones[zone.key]=nil
               for username,u in pairs(settings.users or {}) do if u.zoneId==zone.id then settings.users[username]=nil end end
               for t,s in pairs(sessions) do if s.user and s.user.zoneId==zone.id then sessions[t]=nil end end
            end
            installed(result,e)
         end)
      elseif action=="deviceDelete" then
         if type(data.deviceId)~="string" or data.acknowledge~=true then return reply(nil,"Select a device and confirm deletion.") end
         return manage(function(sql)
            local d=sql("SELECT * FROM devices WHERE id=?",data.deviceId)[1]
            if not d then return {error="Device no longer exists. Refresh the device list."} end
            local zone=config.zones[d.zone_key]
            if not zone or not ownZone(zone.id) then return {error="Zone access denied."} end
            sql("UPDATE orders SET status='invalid' WHERE device_id=? AND status IN ('ready','processing')",d.id)
            sql("DELETE FROM devices WHERE id=?",d.id)
            audit(sql,"admin_device_removed",peer,d.id,d.local_ip,zone.id,account.username)
            return {removed=1}
         end,complete)
      elseif action=="cleanupPreview" then
         local zone=zones[data.id]
         local days=tonumber(data.days)
         if not zone or not days or days%1~=0 or days<1 or days>3650 then return reply(nil,"Choose a zone and 1 to 3650 inactive days.") end
         return manage(function(sql)
            return {devices=sql("SELECT id,label,local_ip,last_peer,last_seen FROM devices WHERE zone_key=? AND last_seen<? ORDER BY last_seen LIMIT 200",zone.key,os.time()-days*86400)}
         end,function(result,e)
            if not result then return complete(result,e) end
            session.preview={token=identity.random(),expires=os.time()+300,devices=result.devices,zone=zone.key}
            result.token=session.preview.token reply(result)
         end)
      elseif action=="cleanupConfirm" then
         local preview=session.preview
         if not preview or preview.expires<os.time() or not identity.equal(preview.token,data.token) or data.acknowledge~=true then return reply(nil,"Create a fresh preview and acknowledge removal.") end
         session.preview=nil
         return manage(function(sql)
            local removed=0
            for _,item in ipairs(preview.devices) do
               local d=sql("SELECT * FROM devices WHERE id=? AND zone_key=? AND last_seen=?",item.id,preview.zone,tonumber(item.last_seen))[1]
               if d then
                  sql("UPDATE orders SET status='invalid' WHERE device_id=? AND status IN ('ready','processing')",d.id)
                  sql("DELETE FROM devices WHERE id=?",d.id)
                  audit(sql,"admin_device_removed",peer,d.id,d.local_ip,config.zones[d.zone_key].id,account.username) removed=removed+1
               end
            end
            return {removed=removed,skipped=#preview.devices-removed}
         end,complete)
      end
      return reply(nil,"Unknown operation.",404)
   end
   function api.close() sessions={} api.loaded=false if sso then sso.close() end end
   return api
end
return M
