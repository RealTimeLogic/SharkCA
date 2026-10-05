-- Standard ACME transport and account/order authorization.
local identity,http=appreq"identity",appreq"http"
local M={}
local function array(t) return setmetatable(t or {},{__jsontype="array"}) end
local function decode64(value)
   if type(value)~="string" or value:find("[^%w_%-]") then return end
   local ok,bytes=pcall(ba.b64decode,value)
   if ok and bytes and ba.b64urlencode(bytes)==value then return bytes end
end
local function publicKey(jwk)
   if type(jwk)~="table" or jwk.kty~="EC" or jwk.crv~="P-256" or jwk.d~=nil then return end
   local x,y=decode64(jwk.x),decode64(jwk.y)
   if not x or #x~=32 or not y or #y~=32 then return end
   local canonical=string.format('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}',jwk.x,jwk.y)
   return {x=x,y=y},ba.b64urlencode(ba.crypto.hash"sha256"(canonical)(true))
end
function M.create(config,db,issuer)
   local allow=http.limiter()
   local nonces,slots,nextSlot={}, {},0
   local function nonce()
      nextSlot=nextSlot%4096+1
      if slots[nextSlot] then nonces[slots[nextSlot]]=nil end
      local value=ba.b64urlencode(ba.rndbs(32))
      nonces[value]=os.time()+300
      slots[nextSlot]=value
      return value
   end
   return function(request,response,path)
      local route=path
      local peer=identity.peer(request:peername())
      local localIp,zoneId="unknown",nil
      local deferred
      if not app.ready then http.log("issuer_unavailable",localIp,peer) return http.send(response,503,{error="Issuer not ready"}) end
      local origin=identity.origin("https://"..(request:header"Host" or ""))
      if not origin or not config.acceptOrigin(origin) then http.log("unknown_portal",localIp,peer) return http.send(response,403,{error="Unknown portal address"}) end
      local base=origin.."/acme/"
      local directory=base.."directory"
      local function send(status,body,headers)
         headers=headers or {}
         headers["Replay-Nonce"]=nonce()
         headers.Link='<'..directory..'>;rel="index"'
         http.send(deferred or response,status,body,headers,deferred~=nil)
      end
      local function problem(code,status,detail)
         http.log("ACME "..code,localIp,peer,zoneId)
         send(status or 400,{type="urn:ietf:params:acme:error:"..code,detail=detail or code,status=status or 400},
            {['Content-Type']='application/problem+json'})
      end
      if not request:issecure() then return problem("malformed",400,"HTTPS is required") end
      if not allow(peer) then return problem("rateLimited",429) end
      if not app.ready then return problem("serverInternal",503,"issuer_unavailable") end
      local method=request:method()
      if route=="root.pem" and method=="GET" then
         return send(200,issuer.root("portal"),{['Content-Type']='application/x-pem-file',
            ['Content-Disposition']='attachment; filename="SharkCA-root.cer"'})
      end
      if route=="directory" and method=="GET" then
         return send(200,{newNonce=base.."nonce",newAccount=base.."new-account",newOrder=base.."new-order",revokeCert=base.."revoke"})
      end
      if route=="nonce" and (method=="GET" or method=="HEAD") then
         response:setstatus(method=="GET" and 204 or 200)
         response:setheader("Replay-Nonce",nonce())
         response:setheader("Cache-Control","no-store")
         return
      end
      if method~="POST" then return problem("malformed",405,"POST required") end
      if (request:header"Content-Type" or ""):lower():match("^%s*([^;%s]+)")~="application/jose+json" then
         return problem("malformed",415,"application/jose+json required")
      end
      local jws,err=http.read(request,16384)
      if not jws then return problem("malformed",err=="body_too_large" and 413 or 400,err) end
      local protected,payload,signature=decode64(jws.protected),decode64(jws.payload),decode64(jws.signature)
      local header=protected and identity.decode(protected)
      if not header or not payload or not signature or #signature~=64 or jws.header~=nil or jws.signatures~=nil or
         header.alg~="ES256" or header.crit~=nil or header.b64~=nil or header.url~=base..route then return problem("malformed") end
      local expires=type(header.nonce)=="string" and nonces[header.nonce]
      if not expires or expires<os.time() then return problem("badNonce") end
      nonces[header.nonce]=nil
      local isNew=route=="new-account"
      if isNew and payload=="" then return problem("malformed") end
      if (isNew and (not header.jwk or header.kid)) or (not isNew and (header.jwk or type(header.kid)~="string")) then
         return problem("malformed")
      end
      local data=payload=="" and {} or identity.decode(payload)
      if not data then return problem("malformed") end
      local accountId
      if not isNew then
         local prefix=base.."account/"
         accountId=header.kid:sub(#prefix+1)
         if header.kid:sub(1,#prefix)~=prefix or not identity.hex(accountId,32) then return problem("accountDoesNotExist",400) end
      end
      deferred=response:deferred()
      response=nil
      local function failure(result,errorCode)
         if not result then problem("serverInternal",503,errorCode) return true end
         if result.error then
            if result.error=="issuer_unavailable" or result.error=="issuer_expiring" or result.error=="signing_failed" then
               problem("serverInternal",503,result.error) return true
            end
            problem(result.error,result.error=="unauthorized" and 403 or result.error=="rateLimited" and 429 or 400)
            return true
         end
      end
      local function accountBody(account)
         return {status=account.status,contact=array(ba.json.decode(account.contact))}
      end
      local function orderBody(order)
         local urls={}
         for i in ipairs(order.identifiers) do urls[i]=base.."authz/"..order.id.."/"..i end
         return {status=order.status,expires=os.date("!%Y-%m-%dT%H:%M:%SZ",tonumber(order.expires)),
            identifiers=order.identifiers,authorizations=urls,finalize=base.."finalize/"..order.id,
            certificate=order.status=="valid" and base.."certificate/"..order.id or nil}
      end
      local function verified(jwk,account)
         local key,thumbprint=publicKey(jwk)
         if not key then return problem("badPublicKey") end
         local der=ba.crypto.sigparams(signature:sub(1,32),signature:sub(33))
         local hash=ba.crypto.hash"sha256"(jws.protected.."."..jws.payload)(true)
         local ok,valid=pcall(ba.crypto.verify,der,hash,key)
         if not ok or not valid then return problem("unauthorized",403) end
         if account and account.device_ip then
            localIp=account.device_ip
            local z=config.zones[account.device_zone] zoneId=z and z.id
         end
         if isNew then
            if data.onlyReturnExisting~=nil and type(data.onlyReturnExisting)~="boolean" then return problem("malformed") end
            if data.termsOfServiceAgreed~=nil and data.termsOfServiceAgreed~=true then return problem("malformed") end
            local contact=data.contact or array()
            if type(contact)~="table" or #contact>4 then return problem("invalidContact") end
            for k,v in pairs(contact) do
               if type(k)~="number" or k<1 or k>#contact or k%1~=0 or type(v)~="string" or
                  #v>254 or not v:match("^mailto:[^%s@]+@[^%s@]+$") then return problem("invalidContact") end
            end
            return db.newAccount(directory,thumbprint,{kty="EC",crv="P-256",x=jwk.x,y=jwk.y},contact,data.onlyReturnExisting,
               function(row,e)
                  if failure(row,e) then return end
                  send(row.created and 201 or 200,accountBody(row),{Location=base.."account/"..row.id})
               end)
         end
         if account.status~="valid" then return problem("unauthorized",403) end
         if route=="revoke" then
            if not decode64(data.certificate) then return problem("malformed") end
            -- Do not report successful revocation until relying parties can consume it.
            return problem("serverInternal",503,"revocation_unavailable")
         end
         if route=="account/"..accountId then
            if payload=="" then return send(200,accountBody(account)) end
            if data.status=="deactivated" then
               return db.deactivate(directory,accountId,function(row,e)
                  if not failure(row,e) then send(200,accountBody(row)) end
               end)
            end
            return problem("malformed",400,"Only account deactivation is currently supported")
         end
         if route=="new-order" then
            if data.notBefore or data.notAfter then return problem("rejectedIdentifier",400,"Custom validity is unavailable") end
            if not identity.identifierKey(data.identifiers) then return problem("malformed") end
            return db.newOrder(directory,accountId,data.identifiers,function(row,e)
               if not failure(row,e) then send(201,orderBody(row),{Location=base.."order/"..row.id}) end
            end)
         end
         local kind,id,index=route:match("^([^/]+)/([0-9a-f]+)/?(%d*)$")
         if not id or #id~=32 or (kind~="order" and kind~="authz" and kind~="finalize" and kind~="certificate") or
            (kind=="authz" and index=="") or (kind~="authz" and index~="") then return problem("malformed",404) end
         if kind~="finalize" and payload~="" then return problem("malformed",400,"POST-as-GET required") end
         if kind=="finalize" and (not decode64(data.csr) or #data.csr<4) then return problem("badCSR") end
         if kind=="certificate" then
            return db.certificate(directory,accountId,id,function(row,e)
               if not failure(row,e) then send(200,row.pem,{['Content-Type']='application/pem-certificate-chain'}) end
            end)
         end
         db.order(directory,accountId,id,function(row,e)
            if failure(row,e) then return end
            for _,identifier in ipairs(row.identifiers) do if identifier.type=="ip" then localIp=identifier.value end end
            if kind=="order" then return send(200,orderBody(row)) end
            if kind=="authz" then
               local identifier=row.identifiers[tonumber(index)]
               if not identifier then return problem("malformed",404) end
               return send(200,{status=row.status~="invalid" and "valid" or "invalid",identifier=identifier,
                  expires=os.date("!%Y-%m-%dT%H:%M:%SZ",tonumber(row.expires)),challenges=array()})
            end
            issuer.issue(directory,accountId,row,decode64(data.csr),function(result,err)
               if not failure(result,err) then send(200,orderBody(result),{Location=base.."order/"..id,['Retry-After']='1'}) end
            end)
         end)
      end
      if isNew then return verified(header.jwk) end
      db.account(directory,accountId,function(account,e)
         if failure(account,e) then return end
         verified(ba.json.decode(account.jwk),account)
      end)
   end
end
return M
