-- Crypto runs outside the registry writer. Only a committed certificate is published.
local authority,csr,identity=appreq"authority",appreq"csr",appreq"identity"
local M={}
function M.create(config,db)
   local worker=ba.thread.create()
   local roots,closing,pending,closeCallback={},false,0
   local api={}
   local function run(operation,callback)
      worker:run(function()
         local ok,result,err=pcall(operation)
         callback(ok and result or nil,ok and err or "signing_failed")
      end)
   end
   function api.ensure(directory,callback)
      if closing then callback(nil,"issuer_closed") return end
      if roots[directory] then callback(true) return end
      db.authority(directory,nil,function(row,err)
         if not row or row.error then callback(nil,err or row.error) return end
         run(function()
            if row.record then
               if row.record.descriptor.curve~=config.ca.curve then return nil,"authority_curve_changed" end
               local ok,e=authority.restore(row.record.descriptor)
               if not ok then return nil,e end
               if row.record.kind=="intermediate" then
                  return authority.import(row.record.descriptor,row.record.chain,row.record.trustRoot)
               end
               return row.record
            end
            local descriptor,e=authority.create(row.id,config.ca.curve)
            if not descriptor then return nil,e end
            return authority.root(descriptor,directory=="portal" and "SharkCA Portal HTTPS" or config.ca.commonName.." "..directory:sub(1,8),config.ca.rootLifetime)
         end,function(record,e)
            if not record then callback(nil,e) return end
            local function loaded(saved,problem)
               if not saved or saved.error then callback(nil,problem or saved.error) return end
               roots[directory]=record
               callback(record.expiresAt>os.time(),record.expiresAt<=os.time() and "issuer_expired" or nil)
            end
            if row.record then loaded(row) else db.authority(directory,record,loaded) end
         end)
      end)
   end
   function api.start(callback)
      local services={"portal"}
      for _,z in pairs(config.zones) do services[#services+1]=z.id end
      local function nextService(i)
         if i>#services then callback(true) return end
         api.ensure(services[i],function(ok,err)
            if not ok and services[i]=="portal" then callback(nil,err) return end
            if not ok then app.alerts.record("issuer_initialization_failed",nil,nil,services[i]) end
            nextService(i+1)
         end)
      end
      nextService(1)
   end
   function api.root(service)
      local r=roots[service or "portal"]
      return r and (r.trustRoot or r.certificate)
   end
   -- Only a committed lifecycle candidate may enter here.
   function api.renewed(record,service) roots[service]=record end
   function api.issue(directory,accountId,order,der,callback)
      if closing or not roots[order.zone_id] then callback(nil,"issuer_unavailable") return end
      if order.status~="ready" and order.status~="processing" and order.status~="valid" then callback({error="orderNotReady"}) return end
      pending=pending+1
      local completed=callback
      callback=function(...)
         pending=pending-1
         local ok,err=pcall(completed,...)
         if closing and pending==0 and closeCallback then closeCallback() closeCallback=nil end
         if not ok then error(err) end
      end
      run(function() return csr.inspect(der,order.identifiers) end,function(request,err)
         if not request then callback({error=err or "badCSR"}) return end
         db.reserve(directory,accountId,order.id,identity.hash(der),config.ca.leafLifetime,function(row,e)
            if not row or row.error or not row.sign then callback(row,e) return end
            local signer=roots[row.zone_id]
            run(function()
               if signer.descriptor.id~=row.issuer_id then return nil,"issuer_changed" end
               local certificate,err=authority.sign(signer,request,row.serial,row.not_before,row.not_after)
               if not certificate then return nil,err end
               local raw=ba.b64decode(certificate:match("%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-%s*(.-)%s*%-%-%-%-%-END CERTIFICATE%-%-%-%-%-"))
               return {pem=certificate,fingerprint=identity.hash(raw)}
            end,function(signed)
               db.complete(row,signed and signed.pem,signed and signed.fingerprint,callback)
            end)
         end)
      end)
   end
   function api.close(callback)
      closing=true
      if pending==0 then callback() else closeCallback=callback end
   end
   return api
end
return M
