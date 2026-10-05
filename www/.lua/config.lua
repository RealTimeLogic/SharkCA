local identity=appreq"identity"
local source=require"loadconf".sharkca or {}
assert(not source.networkMode or source.networkMode=="wan" or source.networkMode=="local","sharkca.networkMode must be wan or local")
local config={networkMode=source.networkMode or "wan",explicitNetworkMode=source.networkMode,zones={}}
assert(source.notifications==nil or type(source.notifications)=="boolean","sharkca.notifications must be a boolean")
config.notifications=source.notifications==true
assert(not config.notifications or type(require"loadconf".log)=="table","Email notifications require Mako log/SMTP configuration")
local ca=source.ca or {}
assert(not ca.curve or ca.curve=="P-256" or ca.curve=="P-384","CA curve must be P-256 or P-384")
assert(not ca.commonName or type(ca.commonName)=="string" and #ca.commonName>0 and #ca.commonName<=48,"CA commonName required (up to 48 bytes)")
config.ca={curve=ca.curve or "P-256",commonName=ca.commonName or "SharkTrust Private CA",rootLifetime=ca.rootLifetime or 315360000,leafLifetime=ca.leafLifetime or 7776000}
for _,name in ipairs{"rootLifetime","leafLifetime"} do
   local value=config.ca[name]
   assert(type(value)=="number" and value%1==0 and value>=3600 and (name=="rootLifetime" or value<=31536000),"invalid CA lifetime")
end
assert(config.ca.rootLifetime>config.ca.leafLifetime+300,"Root lifetime must exceed leaf lifetime")
function config.setOrigin(origin)
   config.adminOrigin=origin
end
function config.addZone(key,zone)
   assert(identity.hex(key,64),"zone keys must be 64 lowercase hex characters")
   assert(type(zone.secret)=="string" and #zone.secret==64 and not zone.secret:find("[^%x]"),"invalid zone secret")
   assert(type(zone.includeIp)=="boolean","zone.includeIp must be explicit")
   local ranges={}
   if zone.includeIp then
      assert(type(zone.allowedRanges)=="table" and #zone.allowedRanges>0,"IP-enabled zones require allowedRanges")
      for _,cidr in ipairs(zone.allowedRanges) do
         ranges[#ranges+1]=assert(identity.range(cidr),"allowedRanges requires canonical IPv4 CIDRs")
      end
   end
   local salt=key:gsub("%x%x",function(pair) return string.char(tonumber(pair,16)) end)
   config.zones[key]={id=zone.id,name=zone.name,includeIp=zone.includeIp,allowedRanges=ranges,portalUrl=zone.portalUrl,
      tls=zone.tls or {issuer="private"},
      proofKey=ba.crypto.PBKDF2("sha256",zone.secret:upper(),salt,1000,32)}
end
function config.acceptOrigin(origin)
   if origin==config.adminOrigin then return true end
   for _,zone in pairs(config.zones) do if zone.portalUrl==origin then return true end end
   return false
end
return config
