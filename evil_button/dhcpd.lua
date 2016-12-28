#!/usr/bin/lua

require "utils"
local sock = require "socket"
udp = sock.udp()
udp:setsockname("*", 67)
udp:settimeout(nil)

local client_mac = "23 23 23 23 23 23"
local client_ip = "c0 a8 00 0a"
local server_ip = "c0 a8 00 01"

function parse_options(opt)
	local opts = {}
	while(#opt > 1) do
		local id = opt:byte(1)
		local len = opt:byte(2)
		local data = opt:sub(3,3+len-1)
		opts[id]=data
		opt = opt:sub(3+len)
	end
	return opts
end

local reply_options = {
	[1] = fromhex("ff ff ff 00"),
	[58] = fromhex("00 00 07 08"),
	[59] = fromhex("00 00 0c 4e"),
	[51] = fromhex("00 00 0e 10"),
	[54] = fromhex("c0 a8 00 01"),
}

function encode_options(opts)
	local buf = ""
	for k,v in pairs(opts) do
		buf = buf .. string.char(k) .. string.char(#v) .. v
	end
	return buf .. string.char(255)
end

function parse_bootp_req(data)
	local tid = data:sub(5,8)
	local client_mac = data:sub(29,29+5)
	local options = parse_options(data:sub(256-15))
	--print(tohex(tid),tohex(client_mac))
	--dump_table(options)
	return tid, client_mac, options
end

function zeroes(n)
	local buf = ""
	for i=1,n do
		buf = buf .. string.char(0)
	end
	return buf
end

function ip2txt(ip)
	return ip:byte(1).."."..ip:byte(2).."."..ip:byte(3).."."..ip:byte(4)
end

function send_response(ip, port, tid, client_mac, opts)
	if opts[53] == fromhex("02") then
		-- discover
		next_server = fromhex(server_ip)
	end
	local buf = fromhex("02 01 06 00") .. tid .. zeroes(2 + 2 + 4) .. ip .. next_server .. zeroes(4)
	buf = buf .. client_mac .. zeroes(10 + 3*16 + 9*16) .. fromhex("63 82 53 63")
	buf = buf .. encode_options(opts) .. zeroes(32)
	local res, err = udp:sendto(buf,ip2txt(ip),port)
	--print(ip2txt(ip),res,err)
end

function is_android(v)
	return v and v:find("android%-dhcp")
end

function handle_request(ip, port, tid, mac, opts)
	print("handle", tohex(mac):gsub(" ",":"), port, tohex(tid):gsub(" ",""))
	local reply_opts = {}
	-- copy options
	for k,v in pairs(reply_options) do
		reply_opts[k]=v
	end
	if opts[53] == fromhex("01") then
		-- discover
		reply_opts[53]=fromhex("02")			-- offer
	elseif opts[53] == fromhex("03") then
		-- request
		reply_opts[53]=fromhex("05")			-- offer
	end
	return send_response(fromhex(client_ip),port,tid,mac,reply_opts)
end

os.execute("arp -s "..ip2txt(fromhex(client_ip)).." "..client_mac:gsub(" ", ":"))

while true do
    local data, ip, port = udp:receivefrom()
    local tid, mac, opts = parse_bootp_req(data)
    if mac == fromhex(client_mac) then
		handle_request(ip, port, tid, mac, opts)
	end
    --print(ip,port,tohex(data))
end
