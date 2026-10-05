local identity=appreq"identity"
local M={}
function M.log(code,localIp,peer,zoneId)
   trace(string.format("SharkCA: %s [zone=%s; device IP=%s; WAN IP=%s]",code,zoneId or "portal",localIp or "unknown",peer or "unknown"))
   if app.alerts then app.alerts.record(code,localIp,peer,zoneId) end
end
function M.limiter()
   local peers,count,window={},0,os.time()
   return function(peer)
      if os.time()-window>=60 then peers={} count=0 window=os.time() end
      if not peers[peer] then
         if count>=1024 then return false end
         count=count+1 peers[peer]=0
      end
      peers[peer]=peers[peer]+1
      return peers[peer]<=300
   end
end
function M.send(response,status,body,headers,deferred)
   if deferred and not response:valid() then return end
   response:setstatus(status)
   response:setheader("Cache-Control","no-store")
   response:setheader("Content-Type",headers and headers["Content-Type"] or "application/json")
   for k,v in pairs(headers or {}) do if k~="Content-Type" then response:setheader(k,v) end end
   if deferred then
      local raw=type(body)=="string" and body or ba.json.encode(body)
      response:setcontentlength(#raw)
      response:send(raw)
      response:close()
   else
      local raw=type(body)=="string" and body or ba.json.encode(body)
      response:setcontentlength(#raw)
      response:write(raw)
   end
end
function M.read(request,limit)
   local length=tonumber(request:header"Content-Length")
   if length and length>limit then return nil,"body_too_large" end
   local chunks,size={},0
   local ok=pcall(function()
      for chunk in request:rawrdr(512) do
         size=size+#chunk
         if size>limit then return end
         chunks[#chunks+1]=chunk
      end
   end)
   if size>limit then return nil,"body_too_large" end
   if not ok then return nil,"invalid_json" end
   local raw=table.concat(chunks)
   local data=identity.decode(raw)
   if not data then return nil,"invalid_json" end
   return data,raw
end
return M
