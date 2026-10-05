-- Private SAN certificate plus public certificates selected by SNI. Issuance
-- is separate from installation: persist a complete set before replacing TLS.
local identity,authority=appreq"identity",appreq"authority"
local M={}
function M.create(config,db)
   local api={status="pending"}
   local worker=ba.thread.create()
   local busy,closed,installed,restored=false,false,nil,false
   local callbacks={}
   local public,retired,cachedPublic={},{},{}
   local revision=0
   local onClosed,closing= nil,0
   local function drain()
      for i=#retired,1,-1 do
         local manager=retired[i]
         -- close() can report busy while its installer is awaiting our refresh.
         closing=closing+1
         local ok=manager:close(function() closing=closing-1 if closed and not busy and closing==0 and #retired==0 and onClosed then local cb=onClosed onClosed=nil cb() end end)
         if ok then table.remove(retired,i) else closing=closing-1 end
      end
      if closed and not busy and closing==0 and #retired==0 and onClosed then local cb=onClosed onClosed=nil cb() end
   end
   local function host(origin) return origin and origin:match("^https://([^:]+)") end
   local function desired()
      local result={}
      for _,z in pairs(config.zones) do
         if z.portalUrl and z.tls.issuer=="letsencrypt" then result[host(z.portalUrl)]=z.tls end
      end
      return result
   end
   local function prepareRecords(records)
      local shark=ba.create.sharkssl(nil,{server=true})
      for _,record in ipairs(records) do
         local key=record.privateKey
         assert(type(key)=="table" and key.provider=="tpm","TPM key required")
         if not ba.tpm.haskey(key.name) then assert(ba.tpm.createkey(key.name,key.options)) end
         assert(shark:addcert(assert(ba.tpm.sharkcert(key.name,record.certificate))))
      end
      return shark
   end
   local function installRecords(shark)
      assert(ba.slcon or ba.slcon6,"HTTPS listener unavailable")
      local options={shark=shark}
      if ba.slcon then ba.slcon=assert(ba.create.servcon(ba.slcon,options)) end
      if ba.slcon6 then ba.slcon6=assert(ba.create.servcon(ba.slcon6,options)) end
   end
   local function publicManagers()
      local wanted=desired()
      for name,p in pairs(public) do
         if not wanted[name] or p.email~=wanted[name].email then
            public[name]=nil p.alive=false
            if p.manager then p.manager:stop() retired[#retired+1]=p.manager end
         end
      end
      for name,tls in pairs(wanted) do
         if not public[name] then
            local p={email=tls.email,alive=true,status="pending",record=cachedPublic[name]}
            public[name]=p
            local fileIo=ba.openio"home"
            local base="sharkca-https"
            local ok,err=pcall(function()
               if not fileIo:stat(base) then assert(fileIo:mkdir(base)) end
               p.manager=assert(require"acme/runtime".createManager{io=fileIo,
                  path=base.."/"..identity.hash(name),
                  engine=assert(require"acme/engine".create()),
                  install=function(records,done)
                     if closed or not p.alive then done(nil,"listener_closed") return end
                     if not records[1] then done(true) return end
                     p.record=records[1] cachedPublic[name]=p.record p.status="installing"
                     api.refresh(function(ok,e)
                        if ok and p.alive then p.status="installed" p.error=nil
                        else p.status="failed" p.error=tostring(e or "configuration_changed") end
                        done(ok,e)
                     end)
                  end})
               assert(p.manager:configure{email=tls.email,domains={name},acceptTerms=true,
                  key={type="ecc",curve="SECP256R1"},service={production=true,
                     -- Portal requests always use public trust, independently of device-client defaults.
                     http={shark=ba.sharkclient()}}})
            end)
            if not ok then p.status="failed" p.error=tostring(err) end
         end
         local p=public[name]
         local state=p.manager and p.manager:status()
         if state and state.retryAt~=p.reportedRetry then
            p.reportedRetry=state.retryAt
            if state.retryAt and app.alerts then app.alerts.record("portal_https_renewal_failed") end
         end
         if p.manager and not p.starting and not p.manager:status().started and (not p.retryAt or os.time()>=p.retryAt) then
            p.starting=true p.status="requesting"
            p.manager:start(function(_,e)
               p.starting=false
               if e then
                  p.status="failed" p.error=e.message or e.code p.retryAt=os.time()+(e.temporary and e.retryable and 300 or 3600)
                  if app.alerts then app.alerts.record("portal_https_issuance_failed") end
               end
            end)
         end
      end
      drain()
   end
   function api.zoneStatus(origin)
      local p=public[host(origin)]
      if p then
         local state=p.manager and p.manager:status()
         local record=state and state.domains[host(origin)]
         return {status=state and state.retryAt and "renewal_failed" or p.status,
            error=state and state.retryAt and state.lastError and state.lastError.message or p.error,
            expiresAt=record and record.expiresAt}
      end
      return {status=api.status,error=api.error,expiresAt=api.expiresAt}
   end
   local function names()
      local set={}
      local function add(origin)
         local name=host(origin)
         if name and not (public[name] and public[name].record) then set[name]=true end
      end
      add(config.adminOrigin)
      for _,z in pairs(config.zones) do add(z.portalUrl) end
      local hosts={} for host in pairs(set) do hosts[#hosts+1]=host end table.sort(hosts)
      -- Keep a private default for IP/no-SNI clients and local administration.
      if not next(set) then hosts={"localhost"} end
      local records,signature={},table.concat(hosts,";")
      local ordered={} for name,p in pairs(public) do if p.record then ordered[#ordered+1]=name end end table.sort(ordered)
      for _,name in ipairs(ordered) do records[#records+1]=public[name].record signature=signature..public[name].record.certificate end
      return hosts,table.concat(hosts,";"),records,signature
   end
   local function finish(ok,err)
      busy=false api.status=ok and "installed" or "failed" api.error=err
      local pending=callbacks callbacks={}
      for _,cb in ipairs(pending) do cb(ok,err) end
      drain()
      if not ok then
         trace("SharkCA: HTTPS certificate update failed: "..tostring(err))
         if app.alerts then app.alerts.record("portal_https_installation_failed") end
      end
   end
   function api.refresh(callback)
      if closed then if callback then callback(nil,"listener_closed") end return end
      if callback then callbacks[#callbacks+1]=callback end
      revision=revision+1
      if busy then return end
      if not app.ready then finish(nil,"issuer_not_ready") return end
      busy=true api.status="updating"
      if not restored then
         db.manage(function(sql)
            sql("CREATE TABLE IF NOT EXISTS portal_tls_active(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)")
            local row=sql("SELECT record FROM portal_tls_active WHERE id=1")[1]
            return row and ba.json.decode(row.record) or {}
         end,function(records,e)
            if not records then finish(nil,e) return end
            if closed then finish(nil,"listener_closed") return end
            if records[1] then
               local ok,err=pcall(function() installRecords(prepareRecords(records)) end)
               if not ok then finish(nil,tostring(err)) return end
               for i=2,#records do cachedPublic[records[i].domain]=records[i] end
            end
            restored=true busy=false api.refresh()
         end)
         return
      end
      publicManagers()
      local version=revision
      local hosts,signature,publicRecords,selection=names()
      db.manage(function(sql)
         sql("CREATE TABLE IF NOT EXISTS portal_listener(id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)")
         local row=sql("SELECT record FROM portal_listener WHERE id=1")[1]
         local saved=row and ba.json.decode(row.record)
         local ca=sql("SELECT * FROM authorities WHERE service='portal'")[1]
         if not ca or not ca.record then return {error="issuer_unavailable"} end
         local root=ba.json.decode(ca.record)
         local lifetime=math.min(config.ca.leafLifetime,tonumber(root.expiresAt)-os.time())
         if lifetime<3600 then return {error="issuer_expiring"} end
         if saved and saved.issuer==ca.id and saved.names==signature and saved.expiresAt>os.time()+math.min(604800,lifetime/3) then
            return {saved=saved}
         end
         local serial=tonumber(ca.next_serial)
         sql("UPDATE authorities SET next_serial=next_serial+1 WHERE service='portal'")
         return {root=root,issuer=ca.id,serial=serial,expiresAt=os.time()+lifetime}
      end,function(result,err)
         if not result or result.error then finish(nil,err or result.error) return end
         worker:run(function()
            local ok,record=pcall(function()
               if closed then error("listener_closed") end
               if result.saved then return result.saved end
               local key={provider="tpm",name="SharkCA.listener."..result.issuer,options={key="ecc",curve="SECP256R1"}}
               if not ba.tpm.haskey(key.name) then assert(ba.tpm.createkey(key.name,key.options)) end
               local san={} for i,host in ipairs(hosts) do san[i]=(identity.ip(host) and "IP:" or "")..host end
               local csr=assert(ba.tpm.createcsr(key.name,{commonname="SharkCA Portal"},table.concat(san,";"),{"SSL_SERVER"},{"DIGITAL_SIGNATURE"},"sha256"))
               local identifiers={}
               for i,host in ipairs(hosts) do identifiers[i]={type=identity.ip(host) and "ip" or "dns",value=host} end
               local pem=assert(authority.sign(result.root,{pem=csr,identifiers=identifiers},result.serial,math.max(os.time()-300,result.root.notBefore or 0),result.expiresAt))
               return {names=signature,issuer=result.issuer,expiresAt=result.expiresAt,certificate=pem,privateKey=key}
            end)
            if not ok then finish(nil,"listener_signing_failed") return end
            local function install(saved,e)
               if closed then finish(nil,"listener_closed") return end
               if not saved then finish(nil,e) return end
               local _,_,_,current=names()
               if current~=selection or revision~=version then busy=false api.refresh() return end
               local marker=record.certificate..selection
               if installed==marker then finish(true) return end
               local records={record} for _,r in ipairs(publicRecords) do records[#records+1]=r end
               local prepared,shark=pcall(prepareRecords,records)
               if not prepared then finish(nil,tostring(shark)) return end
               db.manage(function(sql)
                  sql("INSERT OR REPLACE INTO portal_tls_active VALUES(1,?)",ba.json.encode(records))
                  return true
               end,function(saved,e)
                  if closed then finish(nil,"listener_closed") return end
                  if not saved then finish(nil,e) return end
                  local _,_,_,latest=names()
                  if latest~=selection or revision~=version then busy=false api.refresh() return end
                  local success,problem=pcall(installRecords,shark)
                  if not success then finish(nil,tostring(problem)) return end
                  installed=marker api.expiresAt=record.expiresAt
                  finish(true)
               end)
            end
            if result.saved then install(true) else
               db.manage(function(sql)
                  sql("INSERT OR REPLACE INTO portal_listener(id,record) VALUES(1,?)",ba.json.encode(record))
                  return true
               end,install)
            end
         end)
      end)
   end
   local timer=ba.timer(function() if not closed and app.ready then api.refresh() end return not closed end)
   timer:set(math.min(60000,config.ca.leafLifetime*1000//6))
   function api.close(callback)
      closed=true timer:cancel()
      onClosed=callback
      for _,p in pairs(public) do
         p.alive=false
         if p.manager then p.manager:stop() retired[#retired+1]=p.manager end
      end
      public={}
      drain()
   end
   return api
end
return M
