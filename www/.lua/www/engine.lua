-- The SharkTrustX dashboard convention: one cached private LSP template.
local fp=assert(io:open(".lua/www/template.lsp"))
local code,err=ba.parselsp(fp:read"*a") fp:close()
local template=assert(load(assert(code,err),"SharkCA dashboard","t"))
local menu={{"available","Available Devices"},{"overview","Overview"},{"zones","Zones"},{"devices","All devices"},{"certificates","Certificates"},{"authorities","Certificate authority"},{"activity","Activity"},{"account","Administrator"}}
return function(env,view,appIo,page,app)
   env.pageView,env.pageMenu=view,menu
   for _,item in ipairs(menu) do if item[1]==view then env.pageTitle=item[2] end end
   template(env,view,appIo,page,app)
end
