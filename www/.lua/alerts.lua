-- Bounded diagnostic batches; database work and SMTP never share a transaction.
local M={}
local activityOnly={unknown_portal=true,sso_request_rejected=true}
function M.create(config,db)
   local worker=ba.thread.create()
   local pending,count={},0
   local loaded,closed,flushing,sending=false,false,false,false
   local nextMail=0
   local api={enabled=config.notifications,status=config.notifications and "idle" or "disabled"}
   local function log(code) trace("SharkCA: "..code.." [device IP=unknown; WAN IP=unknown]") end
   function api.record(code,ip,peer,zoneId)
      if closed then return end
      -- Callers supply internal codes and parsed IP addresses, never remote text.
      local key=(zoneId or "portal").."|"..code.."|"..(ip or "unknown").."|"..(peer or "unknown")
      local event=pending[key]
      if event then event.count=event.count+1 event.last=os.time() return end
      if count>=128 then return end
      count=count+1
      pending[key]={zoneId=zoneId,code=code,ip=ip or "unknown",peer=peer or "unknown",first=os.time(),last=os.time(),count=1}
   end
   function api.initialize(callback)
      db.manage(function(sql)
         sql([[CREATE TABLE IF NOT EXISTS portal_alerts(id INTEGER PRIMARY KEY,code TEXT NOT NULL,
            local_ip TEXT NOT NULL,peer TEXT NOT NULL,first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,
            occurrences INTEGER NOT NULL,delivery TEXT NOT NULL,zone_id TEXT)]])
         return true
      end,function(ok,err) loaded=ok and true or false callback(ok,err) end)
   end
   function api.flush(callback)
      if not loaded or closed or flushing then if callback then callback(nil,"Alerts unavailable") end return end
      flushing=true
      local batch=pending pending={} count=0
      db.manage(function(sql)
         for _,e in pairs(batch) do
            sql("INSERT INTO portal_alerts(code,local_ip,peer,first_seen,last_seen,occurrences,delivery,zone_id) VALUES(?,?,?,?,?,?,?,?)",
               e.code,e.ip,e.peer,e.first,e.last,e.count,activityOnly[e.code] and "activity_only" or config.notifications and "pending" or "disabled",e.zoneId)
         end
         -- The diagnostic history is bounded independently of the issuance audit.
         sql("DELETE FROM portal_alerts WHERE id NOT IN (SELECT id FROM portal_alerts ORDER BY id DESC LIMIT 1000)")
         return true
      end,function(ok,err)
         flushing=false
         if not ok then
            for _,e in pairs(batch) do
               api.record(e.code,e.ip,e.peer,e.zoneId)
               local key=(e.zoneId or "portal").."|"..e.code.."|"..e.ip.."|"..e.peer
               if pending[key] then pending[key].count=pending[key].count+e.count-1 end
            end
            log("alert_storage_failed")
         end
         if callback then callback(ok,err) end
      end)
   end
   function api.send(callback)
      if closed or not config.notifications then if callback then callback(nil,"Email notifications are disabled.") end return end
      if sending then if callback then callback(nil,"Email delivery is already running.") end return end
      sending=true api.status="sending"
      local function finish(ok)
         sending=false api.status=ok and "sent" or "failed" nextMail=os.time()+(ok and 60 or 300)
         if not ok then log("notification_delivery_failed") end
         if callback then callback(ok,not ok and "Email delivery failed. Check the SMTP configuration." or nil) end
      end
      api.flush(function(ok)
         if not ok then finish(false) return end
         db.manage(function(sql)
            return sql("SELECT * FROM portal_alerts WHERE delivery IN ('pending','failed') ORDER BY id LIMIT 50")
         end,function(rows)
            if not rows then finish(false) return end
            if closed then sending=false return end
            if #rows==0 then sending=false api.status="idle" if callback then callback(true) end return end
            worker:run(function()
               if closed then sending=false return end
               local lines={"SharkTrust Private CA: portal diagnostics", ""}
               for _,e in ipairs(rows) do
                  lines[#lines+1]=string.format("%s UTC: %s (%s occurrence(s)) [zone=%s; device IP=%s; WAN IP=%s]",
                     os.date("!%Y-%m-%d %H:%M:%S",tonumber(e.last_seen)),e.code,e.occurrences,e.zone_id or "portal",e.local_ip,e.peer)
               end
               lines[#lines+1]="\nOpen Activity in the portal for details."
               local called,sent=pcall(function()
                  return require"log".sendmail{subject="SharkCA: portal diagnostics",body=table.concat(lines,"\n")}
               end)
               if closed then sending=false return end
               db.manage(function(sql)
                  for _,e in ipairs(rows) do sql("UPDATE portal_alerts SET delivery=? WHERE id=?",called and sent and "sent" or "failed",e.id) end
                  return true
               end,function(saved) finish(saved and called and sent) end)
            end)
         end)
      end)
   end
   local timer=ba.timer(function()
      if closed then return false end
      if loaded and not flushing and not sending then
         if config.notifications and os.time()>=nextMail then api.send() elseif next(pending) then api.flush() end
      end
      return true
   end)
   timer:set(5000)
   function api.close() closed=true timer:cancel() pending={} end
   return api
end
return M
