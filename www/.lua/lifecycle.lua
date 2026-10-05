-- Operator-controlled CA lifecycle. Preparation never changes the active issuer.
local authority,identity=appreq"authority",appreq"identity"
local M={}
function M.create(config,db)
   local worker=ba.thread.create()
   local closed,busy,loaded=false,false,false
   local onClosed
   local api={}
   local function fingerprint(record) return identity.hash(record.certificate) end
   local function status(record)
      local remaining=record.expiresAt-os.time()
      local state=remaining<=0 and "expired" or remaining<config.ca.leafLifetime and "issuance_blocked" or
         remaining<=31536000 and "expiring" or "valid"
      return {expiresAt=record.expiresAt,renewBefore=record.expiresAt-config.ca.leafLifetime,
         daysRemaining=math.floor(remaining/86400),state=state,fingerprint=fingerprint(record),curve=record.descriptor.curve,
         kind=record.kind or "root"}
   end
   function api.snapshot(sql,service)
      if not loaded then return {state="initializing"} end
      local row=sql("SELECT record FROM authorities WHERE service=?",service)[1]
      if not row or not row.record then return {state="unconfigured"} end
      sql("INSERT OR IGNORE INTO authority_lifecycle(service) VALUES(?)",service)
      local active=ba.json.decode(row.record)
      local result=status(active)
      local saved=sql("SELECT pending,csr FROM authority_lifecycle WHERE service=?",service)[1]
      if saved and saved.pending then
         local pending=ba.json.decode(saved.pending)
         result.pending=status(pending.record)
         result.pending.newKey=pending.record.descriptor.id~=active.descriptor.id
         result.pending.trustFingerprint=identity.hash(pending.record.trustRoot or pending.record.certificate)
      end
      result.csrReady=saved and saved.csr~=nil or false
      result.importSupported=true
      result.retired={}
      for _,row in ipairs(sql("SELECT fingerprint,record,retired FROM authority_history WHERE service=? ORDER BY retired DESC",service)) do
         local item=status(ba.json.decode(row.record)) item.retired=row.retired
         result.retired[#result.retired+1]=item
      end
      return result
   end
   local function monitor()
      if closed or not loaded then return end
      db.manage(function(sql)
         local notices={}
         for _,row in ipairs(sql("SELECT service,record FROM authorities WHERE record IS NOT NULL AND (service='portal' OR service IN (SELECT id FROM portal_zones))")) do
            local service=row.service
            local record=ba.json.decode(row.record)
            local remaining=record.expiresAt-os.time()
            local code
            if remaining<=0 then code="ca_expired"
            elseif remaining<config.ca.leafLifetime then code="ca_issuance_blocked"
            else for _,days in ipairs{1,7,30,90,180,365} do
               if remaining<=days*86400 then code="ca_expiring_"..days.."_days" break end
            end end
            sql("INSERT OR IGNORE INTO authority_lifecycle(service) VALUES(?)",service)
            local marker=fingerprint(record)..":"..tostring(code)
            local saved=sql("SELECT notice FROM authority_lifecycle WHERE service=?",service)[1]
            if saved.notice~=marker then
               sql("UPDATE authority_lifecycle SET notice=? WHERE service=?",marker,service)
               if code then notices[#notices+1]={code=code,zone=service~="portal" and service or nil} end
            end
         end
         return notices
      end,function(result)
         if result and not closed then for _,n in ipairs(result) do app.alerts.record(n.code,nil,nil,n.zone) end end
      end)
   end
   function api.initialize(callback)
      db.manage(function(sql)
         sql([[CREATE TABLE IF NOT EXISTS authority_lifecycle(service TEXT PRIMARY KEY,
            pending TEXT,csr TEXT,descriptor TEXT,notice TEXT)]])
         sql([[CREATE TABLE IF NOT EXISTS authority_history(fingerprint TEXT PRIMARY KEY,
            record TEXT NOT NULL,retired INTEGER NOT NULL,service TEXT)]])
         return true
      end,function(ok,err) loaded=ok and true or false callback(ok,err) if loaded then monitor() end end)
   end
   function api.action(action,data,authorized,peer,callback)
      local service=data.zoneId or "portal"
      if closed or not loaded then callback(nil,"CA lifecycle is unavailable.") return end
      if busy then callback(nil,"Another CA lifecycle operation is running.") return end
      busy=true
      local function finish(result,err)
         busy=false
         local ok,e=pcall(callback,result,err)
         if closed and onClosed then local cb=onClosed onClosed=nil cb() end
         if not ok then error(e) end
      end
      local function manage(operation,done)
         db.manage(function(sql)
            if closed or not authorized() then return {error="Session changed. Sign in again."} end
            sql("INSERT OR IGNORE INTO authority_lifecycle(service) VALUES(?)",service)
            return operation(sql)
         end,function(result,err)
            if not result or result.error then finish(nil,err or result and result.error or "CA storage failed.") else done(result) end
         end)
      end
      local function audit(sql,kind) sql("INSERT INTO audit_events(kind,peer,created,zone_id) VALUES(?,?,?,?)",kind,peer,os.time(),service~="portal" and service or nil) end
      if action=="caActivate" then
         if data.acknowledge~=true then finish(nil,"Confirm that the prepared CA trust has been provisioned to relying clients.") return end
         manage(function(sql)
            local pending=sql("SELECT pending FROM authority_lifecycle WHERE service=?",service)[1].pending
            if not pending then return {error="Prepare a CA certificate first."} end
            pending=ba.json.decode(pending)
            local current=sql("SELECT record FROM authorities WHERE service=?",service)[1].record
            if data.fingerprint~=fingerprint(pending.record) or current~=pending.previous then return {error="CA selection changed. Refresh and review again."} end
            if pending.record.expiresAt<=os.time()+config.ca.leafLifetime then return {error="Prepared root expires too soon. Prepare another renewal."} end
            if (pending.record.notBefore or 0)>os.time() then return {error="Prepared CA is not yet valid. Check the system clock."} end
            local ok,restored=pcall(authority.restore,pending.record.descriptor)
            if not ok or not restored then return {error="The prepared CA does not match this TPM identity."} end
            sql("INSERT OR IGNORE INTO authority_history(fingerprint,record,retired,service) VALUES(?,?,?,?)",fingerprint(ba.json.decode(current)),current,os.time(),service)
            local newKey=pending.record.descriptor.id~=ba.json.decode(current).descriptor.id
            if newKey then
               sql("UPDATE authorities SET id=?,record=?,next_serial=2 WHERE service=?",
                  pending.record.descriptor.id,ba.json.encode(pending.record),service)
               sql("UPDATE orders SET status='invalid' WHERE status='processing' AND zone_id=?",service)
            else sql("UPDATE authorities SET record=? WHERE service=?",ba.json.encode(pending.record),service) end
            sql("UPDATE authority_lifecycle SET pending=NULL,notice=NULL WHERE service=?",service)
            if pending.record.kind=="intermediate" then sql("UPDATE authority_lifecycle SET csr=NULL,descriptor=NULL WHERE service=?",service) end
            audit(sql,newKey and "ca_key_rotated" or "ca_root_renewed")
            return pending.record
         end,function(record)
            app.issuer.renewed(record,service)
            if closed then finish({ok=true}) return end
            if service~="portal" then finish({ok=true}) monitor() return end
            app.ready=true
            -- A changed issuer ID forces a new portal listener certificate.
            app.listener.refresh(function(ok,err)
               finish({ok=true,warning=not ok and "CA activated; check portal HTTPS status." or nil})
            end)
            monitor()
         end)
      elseif action=="caDiscard" then
         manage(function(sql)
            sql("UPDATE authority_lifecycle SET pending=NULL WHERE service=?",service) audit(sql,"ca_renewal_discarded") return {ok=true}
         end,finish)
      elseif action=="caDownload" then
         manage(function(sql)
            local row=sql("SELECT pending,csr FROM authority_lifecycle WHERE service=?",service)[1]
            if data.kind=="active" then
               local ca=sql("SELECT record FROM authorities WHERE service=?",service)[1]
               if not ca or not ca.record then return {error="CA not ready."} end
               local record=ba.json.decode(ca.record)
               return {pem=record.trustRoot or record.certificate,filename="SharkCA-"..service.."-root.cer"}
            elseif data.kind=="csr" then
               if not row.csr then return {error="Create an intermediate CSR first."} end
               return {pem=row.csr,filename="SharkCA-intermediate.csr"}
            elseif data.kind=="renewal" then
               if not row.pending then return {error="Prepare a renewed root first."} end
               local record=ba.json.decode(row.pending).record
               return {pem=record.trustRoot or record.certificate,filename="SharkCA-prepared-root.cer"}
            elseif data.kind=="history" then
               local old=sql("SELECT record FROM authority_history WHERE fingerprint=? AND service=?",data.fingerprint or "",service)[1]
               if not old then return {error="Archived CA not found."} end
               local record=ba.json.decode(old.record)
               return {pem=record.trustRoot or record.certificate,filename="SharkCA-previous-root.cer"}
            end
            return {error="Choose a CSR or renewed-root download."}
         end,finish)
      elseif action=="caPrepare" or action=="caRotate" or action=="caCsr" or action=="caImport" then
         manage(function(sql)
            local row=sql("SELECT * FROM authorities WHERE service=?",service)[1]
            if not row or not row.record then return {error="Initialize the CA first."} end
            local saved=sql("SELECT * FROM authority_lifecycle WHERE service=?",service)[1]
            if action=="caImport" and (not saved.descriptor or data.trustAnchorApproved~=true) then
               return {error="Create a CSR and confirm the independently obtained trust anchor before importing."}
            end
            if action~="caCsr" then
               if saved.pending then return {error="Download, activate or discard the existing renewal first."} end
               if action=="caPrepare" then
                  if ba.json.decode(row.record).kind=="intermediate" then return {error="An external CA must sign intermediate renewals. Create a new CSR instead."} end
                  sql("UPDATE authorities SET next_serial=next_serial+1 WHERE service=?",service)
               end
            elseif saved.csr then return {existing=true} end
            return {previous=row.record,serial=tonumber(row.next_serial),descriptor=saved.descriptor}
         end,function(input)
            if input.existing then finish({ok=true}) return end
            worker:run(function()
               local ok,result=pcall(function()
                  if closed then error("closed") end
                  local old=ba.json.decode(input.previous)
                  if action=="caImport" then
                     local record=authority.import(ba.json.decode(input.descriptor),data.chain,data.root)
                     assert(record.expiresAt>os.time()+config.ca.leafLifetime,"CA chain expires too soon")
                     return {previous=input.previous,record=record}
                  end
                  if action=="caCsr" then
                     local descriptor=assert(authority.create(identity.random(),old.descriptor.curve))
                     return {descriptor=descriptor,csr=assert(authority.csr(descriptor,{commonname="SharkTrust Private CA Intermediate"}))}
                  end
                  local descriptor=old.descriptor
                  if action=="caRotate" then descriptor=assert(authority.create(identity.random(),old.descriptor.curve))
                  else assert(authority.restore(descriptor)) end
                  local record=assert(authority.root(descriptor,old.commonName,config.ca.rootLifetime,action=="caRotate" and 1 or input.serial))
                  if action=="caPrepare" then assert(record.expiresAt>old.expiresAt,"renewal must extend validity") end
                  return {previous=input.previous,record=record}
               end)
               if not ok then finish(nil,action=="caImport" and "CA import rejected. Check the CSR key, certificate chain, trusted root, validity and supported CA constraints." or "CA preparation failed. Check TPM access and the configured root lifetime.") return end
               manage(function(sql)
                  if sql("SELECT record FROM authorities WHERE service=?",service)[1].record~=input.previous then return {error="CA changed. Retry preparation."} end
                  if action=="caCsr" then
                     sql("UPDATE authority_lifecycle SET csr=?,descriptor=? WHERE service=?",result.csr,ba.json.encode(result.descriptor),service)
                     audit(sql,"ca_intermediate_csr_created")
                  else
                     sql("UPDATE authority_lifecycle SET pending=? WHERE service=?",ba.json.encode(result),service)
                     audit(sql,action=="caRotate" and "ca_rotation_prepared" or action=="caImport" and "ca_intermediate_prepared" or "ca_renewal_prepared")
                  end
                  return {ok=true}
               end,finish)
            end)
         end)
      else finish(nil,"Unsupported CA lifecycle action.") end
   end
   local timer=ba.timer(function() monitor() return not closed end)
   timer:set(3600000)
   function api.close(callback)
      closed=true timer:cancel()
      if busy then onClosed=callback elseif callback then callback() end
   end
   return api
end
return M
