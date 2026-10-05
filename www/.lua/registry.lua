-- One thread owns this database, including schema creation and all reads.
-- Callbacks run after commit. No network or PKI work belongs in a transaction.
local identity=appreq"identity"
local M={}
function M.open(config,ready)
   local writer=ba.thread.create()
   local env,conn,failed,closing
   local api={}
   local function sql(query,...)
      local values=table.pack(...)
      local stmt=assert(conn:prepare(query))
      local bindings={}
      for i=1,values.n do
         local v=values[i]
         bindings[i]=v==nil and {"NULL",0} or {type(v)=="number" and "INTEGER" or "TEXT",v}
      end
      if values.n>0 then assert(stmt:bind(bindings)) end
      local result,err=stmt:execute()
      if not result then stmt:close() error(err) end
      local rows={}
      if type(result)=="userdata" then
         local row=result:fetch({},"a")
         while row do rows[#rows+1]=row row=result:fetch({},"a") end
         result:close()
      end
      stmt:close()
      return rows
   end
   local function one(query,...) return sql(query,...)[1] end
   local function done(callback,...)
      local ok=pcall(callback,...)
      if not ok then trace("SharkCA: database completion callback failed") end
   end
   local function submit(operation,callback)
      if closing then done(callback,nil,"database_closed") return end
      writer:run(function()
         if failed then done(callback,nil,"database_unavailable") return end
         local ok,result=pcall(operation)
         if ok then ok=conn:commit("IMMEDIATE") end
         if not ok then
            if not conn:rollback("IMMEDIATE") then failed=true end
            done(callback,nil,"database_unavailable")
         else done(callback,result) end
      end)
   end
   local function fault(code) return {error=code} end
   -- Private administration shares the same serialized transaction owner.
   function api.manage(operation,callback) submit(function() return operation(sql) end,callback) end
   local function zone(device) return config.zones[device.zone_key] end
   local function group(device) return one("SELECT * FROM network_groups WHERE id=?",device.group_id) end
   local function audit(kind,device,peer,ip)
      sql("INSERT INTO audit_events(kind,device_id,local_ip,peer,created,zone_id) VALUES(?,?,?,?,?,?)",
         kind,device and device.id,ip or device and device.local_ip,peer,os.time(),device and zone(device) and zone(device).id)
   end
   local function response(device)
      local z=zone(device)
      if not z then return fault("invalid_credentials") end
      if z.portalUrl and device.directory~=z.portalUrl.."/acme/directory" then return fault("zone_portal_mismatch") end
      if not z.includeIp and not device.label then return fault("name_required") end
      if z.includeIp and not identity.allowed(device.local_ip,z.allowedRanges) then return fault("address_not_allowed") end
      local include=z.includeIp and 1 or 0
      if tonumber(device.include_ip)~=include then
         device.revision=tonumber(device.revision)+1
         device.include_ip=include
         sql("UPDATE devices SET include_ip=?,revision=? WHERE id=?",include,device.revision,device.id)
         sql("UPDATE orders SET status='invalid' WHERE device_id=? AND status IN ('ready','processing')",device.id)
      end
      local g=group(device)
      if tonumber(g.conflicted)==1 then return fault("network_conflict") end
      return {profile="sharkca-v1",registered=true,deviceId=device.id,
         name=device.label and device.label..".local" or nil,
         certificateIdentifiers=identity.identifiers(device.label,device.local_ip,z.includeIp),
         registrationRevision=tonumber(device.revision),
         acmeAccount={directoryUrl=device.directory,keyThumbprint=device.thumbprint}}
   end
   local function invalidate(groupId)
      sql("UPDATE orders SET status='invalid' WHERE group_id=? AND status IN ('ready','processing')",groupId)
   end
   local function observe(device,peer,ip)
      local g=group(device)
      if config.networkMode=="wan" and g.wan~=peer then
         sql("INSERT INTO transitions(group_id,device_id,local_ip,old_wan,new_wan,created) VALUES(?,?,?,?,?,?)",
            g.id,device.id,ip or device.local_ip,g.wan,peer,os.time())
         sql("UPDATE network_groups SET wan=?,revision=revision+1 WHERE id=?",peer,g.id)
         invalidate(g.id)
         local overlaps=sql("SELECT id FROM network_groups WHERE wan=?",peer)
         if #overlaps>1 then
            for _,other in ipairs(overlaps) do
               sql("UPDATE network_groups SET conflicted=1,revision=revision+1 WHERE id=?",other.id)
               invalidate(other.id)
            end
            audit("network_overlap",device,peer,ip)
         end
      end
      if ip and device.local_ip~=ip then
         device.local_ip=ip
         device.revision=tonumber(device.revision)+1
         sql("UPDATE devices SET local_ip=?,revision=? WHERE id=?",ip,device.revision,device.id)
         sql("UPDATE orders SET status='invalid' WHERE device_id=? AND status IN ('ready','processing')",device.id)
      end
      sql("UPDATE devices SET last_peer=?,last_seen=? WHERE id=?",peer,os.time(),device.id)
   end
   function api.register(input,callback)
      submit(function()
         local z=config.zones[input.zoneKey]
         if not z then return fault("invalid_credentials") end
         if z.portalUrl and input.directory~=z.portalUrl.."/acme/directory" then return fault("zone_portal_mismatch") end
         if z.includeIp and not identity.allowed(input.ip,z.allowedRanges) then return fault("address_not_allowed") end
         local old=one("SELECT * FROM devices WHERE credential_hash=?",input.credentialHash)
         if old then
            if old.zone_key~=input.zoneKey or old.directory~=input.directory or
               old.thumbprint~=input.thumbprint or old.requested_label~=input.label then
               return fault("credential_conflict")
            end
            observe(old,input.peer,input.ip)
            return response(old)
         end
         if not z.includeIp and not input.label then return fault("name_required") end
         if one("SELECT id FROM devices WHERE directory=? AND thumbprint=?",input.directory,input.thumbprint) then
            return fault("account_in_use")
         end
         local groups=config.networkMode=="local" and sql("SELECT * FROM network_groups WHERE id='local'") or
            sql("SELECT * FROM network_groups WHERE wan=?",input.peer)
         if #groups>1 or (#groups==1 and tonumber(groups[1].conflicted)==1) then return fault("network_conflict") end
         local g=groups[1]
         if not g then
            g={id=config.networkMode=="local" and "local" or identity.random()}
            sql("INSERT INTO network_groups(id,wan,revision,conflicted) VALUES(?,?,1,0)",g.id,input.peer)
         end
         local label=input.label
         if label then
            local suffix=0
            while one("SELECT id FROM devices WHERE group_id=? AND label=?",g.id,label) do
               if input.namePolicy=="exact" then return fault("name_unavailable") end
               suffix=suffix+1
               if suffix>10000 then return fault("name_unavailable") end
               label=input.label:sub(1,63-#tostring(suffix))..suffix
            end
         end
         local id=identity.random()
         sql([[INSERT INTO devices(id,zone_key,credential_hash,group_id,label,requested_label,
            local_ip,last_peer,last_seen,revision,directory,thumbprint,include_ip) VALUES(?,?,?,?,?,?,?,?,?,1,?,?,?)]],
            id,input.zoneKey,input.credentialHash,g.id,label,input.label,input.ip,input.peer,os.time(),input.directory,input.thumbprint,z.includeIp and 1 or 0)
         local device=one("SELECT * FROM devices WHERE id=?",id)
         audit("registered",device,input.peer)
         return response(device)
      end,callback)
   end
   function api.available(label,peer,callback)
      submit(function()
         local groups=config.networkMode=="local" and sql("SELECT * FROM network_groups WHERE id='local'") or
            sql("SELECT * FROM network_groups WHERE wan=?",peer)
         if #groups>1 or (#groups==1 and tonumber(groups[1].conflicted)==1) then return fault("network_conflict") end
         return {name=label..".local",available=#groups==0 or not one("SELECT id FROM devices WHERE group_id=? AND label=?",groups[1].id,label)}
      end,callback)
   end
   -- authenticate is a portal-owned proof check, never a value from JSON.
   function api.device(input,authenticate,callback)
      submit(function()
         local device=one("SELECT * FROM devices WHERE credential_hash=?",input.credentialHash)
         if not device or not zone(device) or not authenticate(device.zone_key) then return fault("invalid_credentials") end
         input.zoneId=zone(device).id
         input.localIp=device.local_ip -- Authenticated diagnostic context only.
         if input.command=="RemoveDevice" then
            sql("UPDATE orders SET status='invalid' WHERE device_id=?",device.id)
            sql("DELETE FROM devices WHERE id=?",device.id)
            audit("removed",device,input.peer)
            return {removed=true}
         end
         if input.command=="SetAcmeRecord" or input.command=="RemoveAcmeRecord" then
            return input.command=="SetAcmeRecord" and {set=true} or {removed=true} -- Authenticated DNS no-ops.
         end
         if input.command=="GetWan" then return {ipAddress=input.peer} end
         if device.directory~=input.directory or device.thumbprint~=input.thumbprint then return fault("account_mismatch") end
         if input.ip and zone(device).includeIp and not identity.allowed(input.ip,zone(device).allowedRanges) then
            return fault("address_not_allowed")
         end
         observe(device,input.peer,input.ip)
         return response(device)
      end,callback)
   end
   function api.account(directory,id,callback)
      submit(function()
         return one([[SELECT a.*,d.local_ip AS device_ip,d.zone_key AS device_zone FROM accounts a LEFT JOIN devices d
            ON d.directory=a.directory AND d.thumbprint=a.thumbprint WHERE a.directory=? AND a.id=?]],directory,id) or fault("accountDoesNotExist")
      end,callback)
   end
   function api.newAccount(directory,thumbprint,jwk,contact,onlyExisting,callback)
      submit(function()
         local row=one("SELECT * FROM accounts WHERE directory=? AND thumbprint=?",directory,thumbprint)
         if row then return row end
         if onlyExisting then return fault("accountDoesNotExist") end
         local id=identity.random()
         sql("INSERT INTO accounts(id,directory,thumbprint,jwk,contact,status) VALUES(?,?,?,?,?,'valid')",
            id,directory,thumbprint,ba.json.encode(jwk),ba.json.encode(contact))
         row=one("SELECT * FROM accounts WHERE id=?",id)
         row.created=true
         return row
      end,callback)
   end
   function api.deactivate(directory,id,callback)
      submit(function()
         sql("UPDATE accounts SET status='deactivated' WHERE directory=? AND id=?",directory,id)
         sql("UPDATE orders SET status='invalid' WHERE account_id=?",id)
         return one("SELECT * FROM accounts WHERE directory=? AND id=?",directory,id) or fault("accountDoesNotExist")
      end,callback)
   end
   local function approved(directory,thumbprint)
      local device=one("SELECT * FROM devices WHERE directory=? AND thumbprint=?",directory,thumbprint)
      if not device then return nil end
      local registration=response(device)
      if registration.error then return nil end
      return device,group(device),registration.certificateIdentifiers
   end
   local function currentOrder(row)
      local device,g,ids=approved(row.directory,row.thumbprint)
      if (row.status=="ready" or row.status=="processing") and (not device or device.id~=row.device_id or
         tonumber(device.revision)~=tonumber(row.device_revision) or
         tonumber(g.revision)~=tonumber(row.group_revision) or
         identity.identifierKey(ids)~=row.identifier_key or tonumber(row.expires)<=os.time()) then
         sql("UPDATE orders SET status='invalid' WHERE id=?",row.id)
         row.status="invalid"
      end
      row.identifiers=ba.json.decode(row.identifiers)
      return row
   end
   function api.newOrder(directory,accountId,ids,callback)
      submit(function()
         local account=one("SELECT * FROM accounts WHERE directory=? AND id=? AND status='valid'",directory,accountId)
         if not account then return fault("unauthorized") end
         local device,g,approvedIds=approved(directory,account.thumbprint)
         local key=identity.identifierKey(ids)
         if not device or not key or key~=identity.identifierKey(approvedIds) then return fault("rejectedIdentifier") end
         -- Reuse an unfinished order after a lost response; identifiers and revisions must match.
         local old=one([[SELECT * FROM orders WHERE account_id=? AND status='ready' AND
            device_id=? AND device_revision=? AND group_revision=? AND identifier_key=? AND expires>?]],
            accountId,device.id,tonumber(device.revision),tonumber(g.revision),key,os.time())
         if old then return currentOrder(old) end
         if tonumber(one("SELECT count(*) AS n FROM orders").n)>=32768 then return fault("rateLimited") end
         local id=identity.random()
         sql([[INSERT INTO orders(id,device_id,group_id,status,account_id,directory,thumbprint,
            device_revision,group_revision,identifiers,identifier_key,expires,zone_id) VALUES(?,?,?,'ready',?,?,?,?,?,?,?,?,?)]],
            id,device.id,g.id,accountId,directory,account.thumbprint,tonumber(device.revision),tonumber(g.revision),
            ba.json.encode(approvedIds),key,os.time()+900,zone(device).id)
         return currentOrder(one("SELECT * FROM orders WHERE id=?",id))
      end,callback)
   end
   function api.order(directory,accountId,id,callback)
      submit(function()
         if not one("SELECT id FROM accounts WHERE directory=? AND id=? AND status='valid'",directory,accountId) then
            return fault("unauthorized")
         end
         local row=one("SELECT * FROM orders WHERE directory=? AND account_id=? AND id=?",directory,accountId,id)
         if not row then return fault("unauthorized") end
         return currentOrder(row)
      end,callback)
   end
   function api.authority(service,record,callback)
      submit(function()
         local row=one("SELECT * FROM authorities WHERE service=?",service)
         if not row then
            sql("INSERT INTO authorities(service,id,next_serial) VALUES(?,?,2)",service,identity.random())
            row=one("SELECT * FROM authorities WHERE service=?",service)
         end
         if record then
            if record.descriptor.id~=row.id then return fault("authority_mismatch") end
            if row.record and row.record~=ba.json.encode(record) then return fault("authority_already_configured") end
            sql("UPDATE authorities SET record=? WHERE service=?",ba.json.encode(record),service)
            row.record=ba.json.encode(record)
         end
         row.record=row.record and ba.json.decode(row.record)
         return row
      end,callback)
   end
   function api.reserve(directory,accountId,id,csrHash,lifetime,callback)
      submit(function()
         if not one("SELECT id FROM accounts WHERE directory=? AND id=? AND status='valid'",directory,accountId) then
            return fault("unauthorized")
         end
         local row=one("SELECT * FROM orders WHERE directory=? AND account_id=? AND id=?",directory,accountId,id)
         if not row then return fault("unauthorized") end
         row=currentOrder(row)
         if row.csr_hash and row.csr_hash~=csrHash then return fault("badCSR") end
         if row.status=="valid" or row.status=="processing" then return row end
         if row.status~="ready" then return fault("orderNotReady") end
         local ca=one("SELECT * FROM authorities WHERE service=?",row.zone_id)
         if not ca or not ca.record then return fault("issuer_unavailable") end
         local record=ba.json.decode(ca.record)
         local now=os.time()
         if tonumber(record.expiresAt)<now+lifetime then return fault("issuer_expiring") end
         row.serial=tonumber(ca.next_serial)
         row.not_before,row.not_after=math.max(now-300,record.notBefore or 0),now+lifetime
         row.issuer_id,row.csr_hash,row.status,row.sign=ca.id,csrHash,"processing",true
         sql("UPDATE authorities SET next_serial=next_serial+1 WHERE service=?",row.zone_id)
         sql([[UPDATE orders SET status='processing',csr_hash=?,serial=?,not_before=?,not_after=?,issuer_id=? WHERE id=?]],
            csrHash,row.serial,row.not_before,row.not_after,ca.id,id)
         return row
      end,callback)
   end
   function api.complete(reservation,certificate,fingerprint,callback)
      submit(function()
         local row=one("SELECT * FROM orders WHERE id=?",reservation.id)
         if not row then return fault("orderNotReady") end
         row=currentOrder(row)
         local ca=one("SELECT * FROM authorities WHERE service=?",row.zone_id)
         local account=one("SELECT id FROM accounts WHERE id=? AND status='valid'",row.account_id)
         if row.status~="processing" or tonumber(row.serial)~=reservation.serial or row.csr_hash~=reservation.csr_hash or
            not ca or ca.id~=row.issuer_id or not account then return fault("orderNotReady") end
         if not certificate then
            sql("UPDATE orders SET status='invalid' WHERE id=?",row.id)
            return fault("signing_failed")
         end
         sql([[INSERT INTO certificates(id,issuer_id,serial,account_id,directory,pem,fingerprint,not_after,zone_id)
            VALUES(?,?,?,?,?,?,?,?,?)]],row.id,row.issuer_id,tonumber(row.serial),row.account_id,row.directory,certificate,fingerprint,tonumber(row.not_after),row.zone_id)
         sql("UPDATE orders SET status='valid' WHERE id=?",row.id)
         row.status="valid"
         return row
      end,callback)
   end
   function api.certificate(directory,accountId,id,callback)
      submit(function()
         return one("SELECT * FROM certificates WHERE directory=? AND account_id=? AND id=?",directory,accountId,id) or fault("unauthorized")
      end,callback)
   end
   function api.revoke(directory,accountId,fingerprint,reason,callback)
      submit(function()
         local row=one("SELECT * FROM certificates WHERE directory=? AND account_id=? AND fingerprint=?",directory,accountId,fingerprint)
         if not row then return fault("unauthorized") end
         if row.revoked_at then return fault("alreadyRevoked") end
         sql("UPDATE certificates SET revoked_at=?,reason=? WHERE id=?",os.time(),reason,row.id)
         return {}
      end,callback)
   end
   function api.close(callback)
      if closing then return end
      closing=true
      writer:run(function()
         if conn then conn:rollback() conn:close() end
         if env then env:close() end
         if callback then done(callback,true) end
      end)
   end
   writer:run(function()
      local ok,detail=pcall(function()
         env,conn=require"sqlutil".open("sharkca")
         assert(conn)
         conn:setbusytimeout(3000)
         sql("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL,network_mode TEXT NOT NULL)")
         local version=one("SELECT * FROM schema_version")
         if version then
            assert(tonumber(version.version)==4,"Unsupported SharkCA schema")
            assert(not config.explicitNetworkMode or version.network_mode==config.networkMode,"Configured network mode differs from the saved database mode")
            config.networkMode=version.network_mode
         else sql("INSERT INTO schema_version VALUES(4,?)",config.networkMode) end
         sql([[CREATE TABLE IF NOT EXISTS network_groups(id TEXT PRIMARY KEY,wan TEXT NOT NULL,
            revision INTEGER NOT NULL,conflicted INTEGER NOT NULL)]])
         sql("CREATE INDEX IF NOT EXISTS groups_wan ON network_groups(wan)")
         sql([[CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,zone_key TEXT NOT NULL,
            credential_hash TEXT UNIQUE NOT NULL,group_id TEXT NOT NULL,label TEXT,requested_label TEXT,
            local_ip TEXT NOT NULL,last_peer TEXT NOT NULL,last_seen INTEGER NOT NULL,revision INTEGER NOT NULL,
            directory TEXT NOT NULL,thumbprint TEXT NOT NULL,include_ip INTEGER NOT NULL,
            UNIQUE(group_id,label),UNIQUE(directory,thumbprint))]])
         sql([[CREATE TABLE IF NOT EXISTS transitions(id INTEGER PRIMARY KEY,group_id TEXT NOT NULL,
            device_id TEXT NOT NULL,local_ip TEXT NOT NULL,old_wan TEXT NOT NULL,new_wan TEXT NOT NULL,created INTEGER NOT NULL)]])
         sql([[CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,
            device_id TEXT,local_ip TEXT,peer TEXT NOT NULL,created INTEGER NOT NULL,zone_id TEXT,actor TEXT)]])
         sql([[CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,
            group_id TEXT NOT NULL,status TEXT NOT NULL,account_id TEXT NOT NULL,directory TEXT NOT NULL,
            thumbprint TEXT NOT NULL,device_revision INTEGER NOT NULL,group_revision INTEGER NOT NULL,
            identifiers TEXT NOT NULL,identifier_key TEXT NOT NULL,expires INTEGER NOT NULL,
            csr_hash TEXT,serial INTEGER,not_before INTEGER,not_after INTEGER,issuer_id TEXT,zone_id TEXT)]])
         sql([[CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,directory TEXT NOT NULL,
            thumbprint TEXT NOT NULL,jwk TEXT NOT NULL,contact TEXT NOT NULL,status TEXT NOT NULL,
            UNIQUE(directory,thumbprint))]])
         assert(conn:setautocommit("IMMEDIATE"))
         sql([[CREATE TABLE IF NOT EXISTS authorities(service TEXT PRIMARY KEY,id TEXT UNIQUE NOT NULL,
            record TEXT,next_serial INTEGER NOT NULL)]])
         sql([[CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,issuer_id TEXT NOT NULL,serial INTEGER NOT NULL,
            account_id TEXT NOT NULL,directory TEXT NOT NULL,pem TEXT NOT NULL,fingerprint TEXT UNIQUE NOT NULL,
            not_after INTEGER NOT NULL,revoked_at INTEGER,reason INTEGER,zone_id TEXT,UNIQUE(issuer_id,serial))]])
         -- A crash may consume a serial, but must never repeat an uncertain signing operation.
         sql("UPDATE orders SET status='invalid' WHERE status='processing'")
         assert(conn:commit("IMMEDIATE"))
      end)
      failed=not ok
      if not ok then trace("SharkCA: database initialization failed: "..tostring(detail)) end
      done(ready,ok or nil,not ok and "database_unavailable" or nil)
   end)
   return api
end
return M
