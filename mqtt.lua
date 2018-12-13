-- mqtt.lua
--
-- Copyright (c) 2018 Baptiste Assmann bedis9@gmail.com
--
-- This library is free software; you can redistribute it and/or modify it
-- under the terms of the MIT license. See LICENSE for details.
--

local mqtt = { _version = "0.0.1" }

-- get string from a buffer, whose size is encoded over 2 bytes, MSB LSB way
-- the buffer must be in hexa
-- it returns the string and the size of the string
local function getfield(buf, bufsize, pos)
  local msb = tonumber(string.sub(buf, pos, pos + 1), 16)
  pos = pos + 2
  local lsb = tonumber(string.sub(buf, pos, pos + 1), 16)
  pos = pos + 2
  local len = msb * 256 + lsb

  -- ensure we don't read too further in the buffer
  -- len * 2 because the string is encoded in hex
  -- -1 because string index starts at 1
  if pos + len * 2 - 1 > bufsize then
    return '', 0
  end

  local str = ''
  local i = pos
  while i < pos + len * 2 do
    str = str .. string.char(tonumber(string.sub(buf, i, i + 1), 16))
    i = i + 2
  end
  
  -- +4 because the size is encoded on 2 bytes
  return str, len * 2 + 4
end

-- parse flags and return a flag structure with all bits set
local function parseflags(flags)
  if type(flags) ~= 'number' then
    error("expected argument of type number, got " .. type(flags))
  end

  local flag = {}

  flag['username'] = false
  flag['password'] = false
  flag['willretain'] = false
  flag['willqos'] = false
  flag['will'] = false
  flag['clean'] = false
  if flags >= 128 then
    flag['username'] = true
    flags = flags - 128
  end
  if flags >= 64 then
    flag['password'] = true
    flags = flags - 64
  end
  if flags >= 32 then
    flag['willretain'] = true
    flags = flags - 32
  end
  if flags >= 8 then
    flag['willqos'] = true
    flags = flags - 8
  end
  if flags >= 4 then
    flag['will'] = true
    flags = flags - 4
  end
  if flags >= 2 then
    flag['clean'] = true
    flags = flags - 2
  end

  return flag
end


-- dump the content of a mqtt packet to stdout
local function dump_pkt(pkt)
  local str = ''
  if pkt['packettype'] == 1 then
    str = 'CONNECT '
  end
  str = str .. pkt['protocolname'] .. ': '
  str = str .. pkt['clientid']
  if pkt['username'] ~= nil then
    str = str .. ', ' .. pkt['username']
  end
  if pkt['password'] ~= nil then
    str = str .. '/' .. pkt['password']
  end
  print(str)
end


-- buffer must be an hexa representation of a CONNECT packet payload
parse = function(buffer) 
  local pkt = {}
  local cur = 1
  local len = 0
  local buffersize = string.len(buffer)

  pkt['error'] = false
  pkt['errormessgae'] = ''

  -- fixed header
  -- byte 1: packet type is bits from 4 to 7, so we must substract bits from 0 to 3
  pkt['type'] = tonumber(string.sub(buffer, cur, cur + 1), 16) - 15
  if pkt['type'] ~= 1 then
    pkt['error'] = true
    pkt['errormessage'] = 'Wrong packet type: ' .. pkt['type']
    return pkt
  end
  cur = cur + 2

  -- byte 2: remaininig length (len of "payload + payload size")
  -- http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718023
  local multiplier = 1
  local remaininglength = 0
  local encodedByte = tonumber(string.sub(buffer, cur, cur + 1), 16)
  cur = cur + 2
  while (encodedByte >= 128) do
    remaininglength = remaininglength + (encodedByte * multiplier)
    multiplier = multiplier * 128
    if (multiplier > 128 * 128 * 128) then
      pkt['error'] = true
      pkt['errormessage'] = 'announced packet size too big'
      return pkt
    end
    cur = cur + 2
    encodedByte = tonumber(string.sub(buffer, cur, cur + 1), 16)
  end
  if remaininglength * 2 + cur - 1 ~= buffersize then
    pkt['error'] = true
    pkt['errormessage'] = 'announced packet size sem to be wrong, can\'t parse it.'
    return pkt
  end

  -- variable header
  -- protocol name
  pkt['protocolname'], len = getfield(buffer, buffersize, cur)
  cur = cur + len

  -- protocol level
  pkt['protocollevel'] = tonumber(string.sub(buffer, cur, cur + 1), 16)
  cur = cur + 2

  -- flags
  pkt['flag'] = parseflags(tonumber(string.sub(buffer, cur, cur + 1), 16))
  cur = cur + 2

  -- keepalive
  -- encoded over 2 bytes, MSB + LSB
  pkt['keepalive'] = tonumber(string.sub(buffer, cur, cur + 1), 16) * 256 + tonumber(string.sub(buffer, cur + 2, cur + 2 + 1), 16)
  cur = cur + 4


  -- payload
  -- These fields, if present, MUST appear in the following order:
  --   Client Identifier
  --   Will Topic
  --   Will Message
  --   User Name
  --   Password

  -- client identifier
  pkt['clientid'], len = getfield(buffer, buffersize, cur)
  cur = cur + len

  -- will topic
  -- (ignored for now)
  if pkt['flag']['will'] then
    -- skip will topic
    -- size encoded over 2 bytes, MSB + LSB + data len
    cur = cur + 4 + tonumber(string.sub(buffer, cur, cur + 1), 16) * 256 + tonumber(string.sub(buffer, cur + 2, cur + 2 + 1), 16)
    
    -- skip will message
    -- size encoded over 2 bytes, MSB + LSB + data len
    cur = cur + 4 + tonumber(string.sub(buffer, cur, cur + 1), 16) * 256 + tonumber(string.sub(buffer, cur + 2, cur + 2 + 1), 16)
  end

  -- username
  if pkt['flag']['username'] then
    pkt['username'], len = getfield(buffer, buffersize, cur)
    cur = cur + len
  end

  -- password
  if pkt['flag']['password'] then
    pkt['password'], len = getfield(buffer, buffersize, cur)
    cur = cur + len
  end
   
  return pkt
end

function mqtt.parse(buffer)
  if type(buffer) ~= "string" then
    error("expected argument of type string, got " .. type(buffer))
  end
  return ( parse(buffer) )
end

return mqtt
