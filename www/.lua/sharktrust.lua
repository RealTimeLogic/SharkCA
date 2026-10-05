-- Current SharkTrust proof construction, with explicit SharkCA account binding.
local identity,http=appreq"identity",appreq"http"
local M={}
function M.create(config,db)
   local failures={}
   local allow=http.limiter()
   local window=os.time()
   local function proof(zoneKey,value,message)
      local zone=config.zones[zoneKey]
      if not zone then return false end
      local expected=ba.b64urlencode(ba.crypto.hash("hmac","sha256",zone.proofKey)(message)(true,"binary"))
      return identity.equal(value,expected)
   end
   local function binding(data,directory)
      if data.profile~="sharkca-v1" or type(data.acmeAccount)~="table" then return end
      local account=data.acmeAccount
      if type(account.keyThumbprint)~="string" or #account.keyThumbprint~=43 or
         account.keyThumbprint:find("[^%w_%-]") then return end
      if account.directoryUrl==directory then return account end
   end
   return function(request,response)
      local peer=identity.peer(request:peername())
      local localIp,zoneId="unknown",nil
      if os.time()-window>=60 then failures={} window=os.time() end
      local function fail(code,status,deferred)
         -- Never log raw JSON, proof headers, credentials or secrets.
         http.log(code,localIp,peer,zoneId)
         if code=="invalid_credentials" then failures[peer]=(failures[peer] or 0)+1 end
         http.send(deferred or response,status or 400,{error={code=code,message=code}},nil,deferred~=nil)
      end
      if not request:issecure() then return fail("tls_required") end
      local origin=identity.origin("https://"..(request:header"Host" or ""))
      if not origin or not config.acceptOrigin(origin) then return fail("unknown_portal",403) end
      local directory=origin.."/acme/directory"
      if not allow(peer) then return fail("rate_limited",429) end
      if request:method()=="HEAD" then response:setstatus(200) return end
      if request:method()~="POST" then return fail("method_not_allowed",405) end
      if (request:header"Content-Type" or ""):lower():match("^%s*([^;%s]+)")~="application/json" then
         return fail("unsupported_media_type",415)
      end
      if (failures[peer] or 0)>=10 then return fail("rate_limited",429) end
      local data,raw=http.read(request,4096)
      if not data then return fail(raw,raw=="body_too_large" and 413 or 400) end
      localIp=identity.ip(data.ipAddress) or "unknown"
      if data.command=="Capabilities" then
         return http.send(response,200,{result={profiles={"sharkca-v1"},acmeDirectories={directory}}})
      end
      local command=data.command
      if command=="IsAvailable" then
         local key=request:header"X-SharkTrust-Zone-Key"
         if not identity.hex(key,64) or not proof(key,request:header"X-SharkTrust-Proof","SHARKTRUST-AVAILABLE\0"..key.."\0"..raw) then
            return fail("invalid_credentials",401)
         end
         zoneId=config.zones[key].id
         local label=identity.label(data.name)
         if not label then return fail("invalid_name") end
         local deferred=response:deferred()
         response=nil
         return db.available(label,peer,function(result,err)
            if not result or result.error then return fail(err or result.error,err and 503 or 409,deferred) end
            http.send(deferred,200,{result=result},nil,true)
         end)
      end
      if command~="Register" and command~="IsRegistered" and command~="SetIpAddress" and
         command~="SetAcmeRecord" and command~="RemoveAcmeRecord" and command~="GetWan" then return fail("unsupported_command") end
      local account
      if command~="SetAcmeRecord" and command~="RemoveAcmeRecord" and command~="GetWan" then
         account=binding(data,directory)
         if not account then return fail("invalid_account_binding") end
      end
      if (command=="Register" or command=="SetIpAddress") and localIp=="unknown" then return fail("invalid_ip_address") end
      if data.ipAddress~=nil and localIp=="unknown" then return fail("invalid_ip_address") end
      local input={peer=peer,ip=data.ipAddress,command=command,directory=account and account.directoryUrl,
         thumbprint=account and account.keyThumbprint}
      local auth=request:header"X-SharkTrust-Proof"
      if command=="Register" then
         local zoneKey=request:header"X-SharkTrust-Zone-Key"
         if not identity.hex(zoneKey,64) or not proof(zoneKey,auth,"SHARKTRUST-REGISTER\0"..zoneKey.."\0"..raw) then
            return fail("invalid_credentials",401)
         end
         zoneId=config.zones[zoneKey].id
         if config.zones[zoneKey].portalUrl~=origin then return fail("zone_portal_mismatch") end
         if not identity.hex(data.credential,64) then return fail("invalid_device_credential") end
         input.zoneKey=zoneKey
         input.credentialHash=identity.hash(data.credential)
         if data.name~=nil then
            input.label=identity.label(data.name)
            if not input.label then return fail("invalid_name") end
         end
         input.namePolicy=data.namePolicy or "exact"
         if input.namePolicy~="exact" and input.namePolicy~="increment" then return fail("invalid_name_policy") end
         local deferred=response:deferred()
         response=nil
         return db.register(input,function(result,err)
            if not result or result.error then return fail(err or result.error,err and 503 or 409,deferred) end
            result.credential=data.credential -- Pending-credential retry returns the same identity.
            http.send(deferred,200,{result=result},nil,true)
         end)
      end
      local scheme,credential=(request:header"Authorization" or ""):match("^(%S+)%s+(%S+)$")
      if not scheme or scheme:lower()~="bearer" or not identity.hex(credential,64) then return fail("invalid_credentials",401) end
      input.credentialHash=identity.hash(credential)
      local deferred=response:deferred()
      response=nil
      db.device(input,function(zoneKey) return proof(zoneKey,auth,"SHARKTRUST-DEVICE\0"..credential.."\0"..raw) end,
         function(result,err)
            zoneId=input.zoneId
            if localIp=="unknown" then localIp=input.localIp or localIp end
            if not result or result.error then
               local code=err or result.error
               return fail(code,err and 503 or code=="invalid_credentials" and 401 or 409,deferred)
            end
            http.send(deferred,200,{result=result},nil,true)
         end)
   end
end
return M
