<?lsp
if not app.ready then
   return (app.appreq"http").send(response,503,{error={code="database_unavailable",message="Not ready"}})
end
app.sharktrust(request,response)
?>
