-- Bounded portal-side PKCS#10 checks using the existing signature verifier.
-- Compare/replace this boundary in the final updated-native-API milestone.
local identity=appreq"identity"
local M={}
local function hex(s) return (s:gsub(".",function(c) return string.format("%02x",c:byte()) end)) end
local curves={['2a8648ce3d030107']={name="P-256",size=32},['2b81040022']={name="P-384",size=48}}
local hashes={['2a8648ce3d040302']="sha256",['2a8648ce3d040303']="sha384"}
local function inspect(der,expected)
   assert(type(der)=="string" and #der<=8192 and #der>0)
   local nodes=0
   local function node(position,limit,tag)
      nodes=nodes+1 assert(nodes<=256)
      local start=position
      local actual,length=der:byte(position,position+1)
      assert(actual and length and position+1<=limit and actual & 31~=31)
      position=position+2
      if length>=128 then
         local count=length-128
         assert(count>=1 and count<=2 and position+count-1<=limit and der:byte(position)~=0)
         length=0
         for _=1,count do length=(length<<8)|der:byte(position) position=position+1 end
         assert(length>=128 and (count==1 or length>255))
      end
      local last=position+length-1
      assert(last<=limit and (not tag or actual==tag))
      return {tag=actual,start=start,first=position,last=last,next=last+1}
   end
   local function value(n) return der:sub(n.first,n.last) end
   local function raw(n) return der:sub(n.start,n.last) end
   local function children(parent,tags)
      local result,pos={},parent.first
      for _,tag in ipairs(tags) do local n=node(pos,parent.last,tag) result[#result+1]=n pos=n.next end
      assert(pos==parent.next)
      return table.unpack(result)
   end
   local function oid(n) assert(n.tag==6) return hex(value(n)) end
   local top=node(1,#der,48) assert(top.next==#der+1)
   local info,algorithm,signature=children(top,{48,48,3})
   local version,subject,spki,attributes=children(info,{2,48,48,160})
   assert(value(version)=="\0")
   local alg,point=children(spki,{48,3})
   local family,curveOid=children(alg,{6,6})
   assert(oid(family)=="2a8648ce3d0201")
   local curve=assert(curves[oid(curveOid)])
   local key=value(point)
   assert(#key==2+2*curve.size and key:sub(1,2)=="\0\4")
   local pub={x=key:sub(3,2+curve.size),y=key:sub(3+curve.size)}
   local digest=assert(hashes[oid(children(algorithm,{6}))])
   local sig=value(signature) assert(sig:byte(1)==0 and #sig>1)
   local sequence=node(signature.first+1,signature.last,48) assert(sequence.next==signature.next)
   local r,s=children(sequence,{2,2})
   for _,integer in ipairs{r,s} do
      local bytes=value(integer)
      assert(#bytes>0 and #bytes<=curve.size+1 and bytes:byte(1)<128)
      assert(#bytes==1 or bytes:byte(1)~=0 or bytes:byte(2)>=128)
   end
   assert(ba.crypto.verify(sig:sub(2),ba.crypto.hash(digest)(raw(info))(true),pub))
   if subject.first<=subject.last then
      local set=children(subject,{49})
      local attribute=children(set,{48})
      local nameOid=node(attribute.first,attribute.last,6)
      local name=node(nameOid.next,attribute.last)
      assert(oid(nameOid)=="550403" and (name.tag==12 or name.tag==19) and name.next==attribute.next)
      local found=false
      for _,id in ipairs(expected) do if value(name)==id.value then found=true end end
      assert(found)
   end
   local requestAttribute=children(attributes,{48})
   local requestOid,set=children(requestAttribute,{6,49})
   assert(oid(requestOid)=="2a864886f70d01090e")
   local extensions=children(set,{48})
   local seen,ids={},{}
   local pos=extensions.first
   while pos<=extensions.last do
      local extension=node(pos,extensions.last,48) pos=extension.next
      local name=node(extension.first,extension.last,6)
      local id=oid(name) assert(not seen[id]) seen[id]=true
      local data=node(name.next,extension.last)
      if data.tag==1 then
         assert(value(data)=="\255") -- DER default FALSE must be omitted.
         data=node(data.next,extension.last)
      end
      assert(data.tag==4 and data.next==extension.next)
      local inner=node(data.first,data.last)
      assert(inner.next==data.next)
      if id=="551d11" then
         assert(inner.tag==48)
         local p=inner.first
         while p<=inner.last do
            local san=node(p,inner.last) p=san.next
            if san.tag==130 then ids[#ids+1]={type="dns",value=value(san)}
            elseif san.tag==135 then
               local bytes=value(san) assert(#bytes==4)
               ids[#ids+1]={type="ip",value=string.format("%d.%d.%d.%d",bytes:byte(1,4))}
            else error("unsupported SAN") end
         end
      elseif id=="551d0f" then
         local bits=value(inner)
         assert(inner.tag==3 and #bits==2 and bits:byte(1)<=7)
         local padding,mask=bits:byte(1,2)
         assert(mask & ((1<<padding)-1)==0 and mask & ~0xa0==0 and mask & 0x80~=0)
      elseif id=="6086480186f8420101" then
         local bits=value(inner)
         assert(inner.tag==3 and #bits==2 and bits:byte(1)<=7)
         assert(bits:byte(2) & ((1<<bits:byte(1))-1)==0 and bits:byte(2) & ~0xc0==0) -- No CA bits.
      elseif id=="551d13" then
         assert(inner.tag==48 and inner.first>inner.last)
      elseif id=="551d25" then
         assert(inner.tag==48 and oid(children(inner,{6}))=="2b06010505070301")
      else error("unsupported extension") end
   end
   local actual=identity.identifierKey(ids)
   assert(actual and actual==identity.identifierKey(expected))
   return {curve=curve.name,publicKey=ba.b64urlencode(pub.x..pub.y),identifiers=ids,
      pem="-----BEGIN CERTIFICATE REQUEST-----\n"..ba.b64encode(der).."\n-----END CERTIFICATE REQUEST-----\n"}
end
function M.inspect(der,identifiers)
   local ok,result=pcall(inspect,der,identifiers)
   if not ok then return nil,"badCSR" end
   return result
end
return M
