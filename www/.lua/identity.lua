-- Shared portal validation. The embedded client does not load this module.
local M={}
-- Canonical HTTPS origin, without credentials, paths, query or fragments.
function M.origin(value)
   if type(value)~="string" or #value>260 then return end
   local host,port=value:match("^https://([%w%.%-]+):(%d+)/?$")
   if not host then host=value:match("^https://([%w%.%-]+)/?$") end
   if not host or #host>253 or host:find("%.%.") or host:sub(-1)=="." then return end
   host=host:lower()
   for label in host:gmatch("[^.]+") do
      if #label>63 or label:sub(1,1)=="-" or label:sub(-1)=="-" then return end
   end
   if host:sub(1,1)=="." or host:find("[^0-9.]")==nil and not M.ip(host) then return end
   if port then
      port=tonumber(port)
      if port<1 or port>65535 then return end
   end
   local localOnly=host=="localhost" or host:match("%.localhost$") or host:match("^127%.") or host=="0.0.0.0"
   return "https://"..host..(port and port~=443 and ":"..port or ""),localOnly and true or false
end
function M.hex(value,length)
   return type(value)=="string" and #value==length and not value:find("[^0-9a-f]")
end
function M.ip(value)
   if type(value)~="string" then return end
   local a,b,c,d=value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
   if not a then return end
   for _,v in ipairs{a,b,c,d} do
      if #v>3 or tonumber(v)>255 or tostring(tonumber(v))~=v then return end
   end
   return value
end
function M.label(value)
   if type(value)~="string" then return end
   value=value:lower():gsub("%.local%.?$","")
   if #value<1 or #value>63 or value:find("[^a-z0-9%-]") or
      value:sub(1,1)=="-" or value:sub(-1)=="-" then return end
   return value
end
local function ipNumber(value)
   local n=0
   for part in value:gmatch("%d+") do n=(n<<8)|tonumber(part) end
   return n
end
function M.range(value)
   if type(value)~="string" then return end
   local ip,bits=value:match("^(.-)/(%d+)$")
   bits=tonumber(bits)
   if not M.ip(ip) or not bits or bits>32 then return end
   local mask=(0xffffffff << (32-bits)) & 0xffffffff
   local network=ipNumber(ip)
   if network & mask~=network then return end
   return {network=network,mask=mask}
end
function M.allowed(ip,ranges)
   if not M.ip(ip) then return false end
   local n=ipNumber(ip)
   for _,range in ipairs(ranges or {}) do
      if n & range.mask==range.network then return true end
   end
   return false
end
function M.peer(value)
   return value:gsub("^::[fF][fF][fF][fF]:", ""):lower()
end
function M.random()
   return (ba.rndbs(16):gsub(".",function(c) return string.format("%02x",c:byte()) end))
end
function M.hash(value) return ba.crypto.hash"sha256"(value)(true,"hex") end
function M.equal(a,b)
   if type(a)~="string" or type(b)~="string" or #a~=#b then return false end
   local diff=0
   for i=1,#a do diff=diff | (a:byte(i) ~ b:byte(i)) end
   return diff==0
end
function M.decode(raw)
   -- ba.json.decode accepts concatenated JSON; protocol messages must not.
   local values=table.pack(pcall(ba.json.decode,raw))
   if values[1] and values.n==2 and type(values[2])=="table" and raw:match("^%s*{") then
      return values[2]
   end
end
function M.identifiers(label,ip,includeIp)
   local ids={}
   if label then ids[#ids+1]={type="dns",value=label..".local"} end
   if not label or includeIp then ids[#ids+1]={type="ip",value=ip} end
   return ids
end
function M.identifierKey(ids)
   if type(ids)~="table" or #ids<1 or #ids>2 then return end
   local names,seen={},{}
   local count=0
   for key in pairs(ids) do
      count=count+1
      if type(key)~="number" or key<1 or key>#ids or key%1~=0 then return end
   end
   if count~=#ids then return end
   for _,id in ipairs(ids) do
      if type(id)~="table" or (id.type~="dns" and id.type~="ip") or type(id.value)~="string" then return end
      if id.type=="dns" then
         local label=M.label(id.value)
         if not label or id.value~=label..".local" then return end
      elseif not M.ip(id.value) then return end
      if seen[id.type] then return end
      seen[id.type]=true
      names[#names+1]=id.type..":"..id.value
   end
   table.sort(names)
   return table.concat(names,";")
end
return M
