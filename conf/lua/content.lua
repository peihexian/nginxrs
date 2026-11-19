ngx.header["X-Powered-By"] = "mlua"
ngx.header["Content-Type"] = "application/json"
ngx.status = 200
ngx.say('{"message":"hello from Lua","uri":"' .. ngx.var.uri .. '"}')
