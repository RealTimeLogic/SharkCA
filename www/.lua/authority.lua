-- CA key ownership only. Private keys never leave the Mako TPM interface.
-- Issuer profiles are explicit; requested extensions never grant CA privileges.
local M={}
local curves={
   ["P-256"]={name="SECP256R1",bytes=32,hash="sha256"},
   ["P-384"]={name="SECP384R1",bytes=48,hash="sha384"}
}

local function provider()
   local t=ba.tpm
   if not t then return nil,"tpm_required" end
   for _,name in ipairs{"haskey","createkey","keyparams","createcsr","createcertificate"} do
      if type(t[name])~="function" then return nil,"tpm_required" end
   end
   return t
end

local function key(record)
   assert(type(record)=="table" and type(record.id)=="string" and
      #record.id==32 and not record.id:find("[^0-9a-f]"),"invalid authority ID")
   local curve=assert(curves[record.curve],"unsupported authority curve")
   local t,err=provider()
   if not t then return nil,err end
   local name="SharkCA.authority."..record.id.."."..record.curve..".v1"
   if not t.haskey(name) then
      local ok
      ok,err=t.createkey(name,{key="ecc",curve=curve.name})
      if not ok then return nil,err end
   end
   local x,y=t.keyparams(name)
   if not x then return nil,y end
   if #x~=curve.bytes or #y~=curve.bytes then return nil,"tpm_curve_mismatch" end
   local public=ba.b64urlencode(x..y)
   if record.publicKey and record.publicKey~=public then return nil,"tpm_identity_mismatch" end
   return name,curve,t,public
end

-- id: unique 32-character lowercase hex string, allocated by the database owner.
-- curve: P-256 or P-384. Returns a public descriptor, or nil,error.
function M.create(id,curve)
   local record={id=id,curve=curve}
   local name,algorithm,t,public=key(record)
   if not name then return nil,algorithm end
   record.publicKey=public
   return record
end

-- A persisted public descriptor must match this host's recreated TPM identity.
function M.restore(record)
   assert(type(record.publicKey)=="string","missing persisted authority public key")
   local name,err=key(record)
   if not name then return nil,err end
   return true
end

-- dn: BAS distinguished-name table with required string commonname.
-- Returns a public PEM CSR or nil,error; this does not activate an issuer.
function M.csr(record,dn)
   assert(type(dn)=="table" and type(dn.commonname)=="string","authority common name required")
   assert(type(record.publicKey)=="string","missing persisted authority public key")
   local name,algorithm,t=key(record)
   if not name then return nil,algorithm end
   -- Empty SAN suppresses the CSR helper's common-name-as-DNS default for CAs.
   return t.createcsr(name,dn,"",{"SSL_CA"},{"KEY_CERT_SIGN","CRL_SIGN"},algorithm.hash)
end

function M.root(record,commonName,lifetime,serial)
   local name,algorithm,t=key(record)
   if not name then return nil,algorithm end
   local csr,err=M.csr(record,{commonname=commonName})
   if not csr then return nil,err end
   local now=os.time()
   local certificate
   certificate,err=t.createcertificate(name,csr,os.date("!*t",now-300),os.date("!*t",now+lifetime),serial or 1,algorithm.hash,
      {profile="rootCA",pathLen=1})
   if not certificate then return nil,err end
   return {descriptor=record,certificate=certificate,expiresAt=now+lifetime,commonName=commonName}
end

-- Restrict imports to a bounded PEM chain. The trust anchor is selected separately
-- by the administrator; an uploaded chain never selects its own trust policy.
local function certificates(pem)
   assert(type(pem)=="string" and #pem<=60000,"CA PEM input too large")
   local der,canonical={},{}
   local remainder=pem:gsub("%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-%s*([%w+/=%s]+)%s*%-%-%-%-%-END CERTIFICATE%-%-%-%-%-",function(body)
      assert(#der<8,"CA chain too long")
      local raw=assert(ba.b64decode(body))
      assert(#raw>=4 and #raw<=32767,"invalid CA certificate")
      der[#der+1]=raw
      canonical[#canonical+1]="-----BEGIN CERTIFICATE-----\n"..ba.b64encode(raw).."\n-----END CERTIFICATE-----\n"
      return ""
   end)
   assert(#der>0 and not remainder:find("%S"),"Expected PEM certificates only")
   return der,canonical
end
function M.import(descriptor,chainPem,rootPem)
   assert(M.restore(descriptor))
   local chain,pem=certificates(chainPem)
   local root,rootText=certificates(rootPem)
   assert(#root==1,"Select one trust anchor")
   if chain[#chain]~=root[1] then chain[#chain+1]=root[1] pem[#pem+1]=rootText[1] end
   assert(#chain>=2 and #chain<=8,"Expected an intermediate and its parent chain")
   local info=assert(ba.parsecert(chain,root[1],assert(ba.b64decode(descriptor.publicKey)),os.date("!%Y%m%d%H%M%S")))
   local from,to=0,math.maxinteger
   for _,cert in ipairs(info) do
      from=math.max(from,ba.parsecerttime(cert.tzfrom))
      to=math.min(to,ba.parsecerttime(cert.tzto))
   end
   return {descriptor=descriptor,kind="intermediate",certificate=pem[1],
      chain=table.concat(pem,"",1,#pem-1),trustRoot=rootText[1],
      notBefore=from,expiresAt=to,commonName=info[1].subject.commonname}
end

-- Verify the CSR and reserve serial/validity before calling this worker operation.
function M.sign(authority,request,serial,notBefore,notAfter)
   local name,algorithm,t=key(authority.descriptor)
   if not name then return nil,algorithm end
   -- Compare typed names to the enrollment order (or configured listener hosts).
   local expected={}
   for _,id in ipairs(assert(request.identifiers,"approved identifiers required")) do
      local value=id.value
      if id.type=="ip" then value=string.char(value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")) end
      expected[(id.type=="ip" and "IP" or "DNS")..":"..value]=true
   end
   local certificate,err=t.createcertificate(name,request.pem,authority.certificate,
      os.date("!*t",notBefore),os.date("!*t",notAfter),serial,algorithm.hash,
      {profile="tlsServer",approveSANs=function(names)
         if #names~=#request.identifiers then return false end
         for _,san in ipairs(names) do if not expected[san.type..":"..san.value] then return false end end
         return true
      end})
   if not certificate then return nil,err end
   return certificate..(authority.chain or "")
end
return M
