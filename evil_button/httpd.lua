#!/usr/bin/lua

-- load namespace
local socket = require("socket")

require "utils"

local peer_pubkey

function pubkey_handler(method,location,posted)
	local body = ""
	if method == "GET" then
		body = '{"publicKey":"-----BEGIN PUBLIC KEY-----\n<FILLME>==\n-----END PUBLIC KEY-----\n","scheme":0}'
	else
		peer_pubkey = posted:sub(15,-14):gsub("\\n","\n")
		print(peer_pubkey)
	end
	return 200, body
end

function dummy_handler(method,location,posted)
	--print(printable(posted))
	return 200, ""
end

local content = {
	["/"] = '{"amzn_devid":"23","amzn_macid":"23","international":1,"amzn_networks":[{"ssid":"Cyber","bssid":"23","security":"WPA AES PSK","rssi":"-40"},{"ssid":"Cyber2","bssid":"23","security":"WPA AES PSK","rssi":"-75"}],"schemes":[0]}',
	["/pubkey"] = pubkey_handler,
	["/locale"] = dummy_handler,
	["/stoken"] = dummy_handler,
	["/network"] = dummy_handler,
}

function http_response(method, location, posted)
	local body = content[location]
	local status = 200
	if body == nil then
		status = 400
		body = ""
	elseif type(body) == "function" then
		status, body = body(method,location,posted)
	end
	print(method,location,status,type(body),printable(posted))
	local reply = "HTTP/1.1 "..status.." OK\r\n"
	reply = reply .. "Content-type: text/html\r\n"
	return reply.."\r\n"..body
end

-- create a TCP socket and bind it to the local host, at any port
local server = socket.try(socket.bind("*", 80))
server:setoption("reuseaddr", true)
-- find out which port the OS chose for us
local ip, port = server:getsockname()
-- loop forever waiting for clients
while 1 do
  -- wait for a conection from any client
  local client = server:accept()
  local line, err
  local loc, method
  local body = nil
  local body_len = 0
  repeat
	line, err = client:receive()
	if line and not err then
	   --print(line)
	  if line:find("HTTP/1.1") then
		method, loc = line:match("(%g+) (%g+) ")
		--print(method,loc)
	  elseif #line == 0 then -- end of header
		--print(#line)
		if method == "POST" then
			body = client:receive(body_len)
			--print("POST len "..body_len)
		end
	    client:send(http_response(method,loc,body))
	    client:close()
	  --print(line)
	  else
   		  local len = line:match("Content%-Length: (%d+)")
		  if len then body_len = len end
	  end
	end
  until err
  client:close()
  --print(method,loc)
end
