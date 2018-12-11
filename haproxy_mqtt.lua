-- haproxy_mqtt.lua
--
-- Copyright (c) 2018 Baptiste Assmann bedis9@gmail.com
--
-- This library is free software; you can redistribute it and/or modify it
-- under the terms of the MIT license. See LICENSE for details.
--
local mqtt = require 'mqtt'
local debug = false


--[[--
  type: converter
  purpose: ensures a buffer contains a MQTT CONNECT message
  arguments: buffer: hex representation of a binary payload
  return: boolean (HAProxy string),
          * true if the buffer contains well a CONNECT message
	  * false otherwise
  configuration example: 
    tcp-request content accept if { req.payload(0,0),hex,lua.is_mqtt_connect,bool }
--]]--
local function is_mqtt_connect(buffer)
  if string.len(buffer) < 8 then
    return false
  end

  local mqttpkt = mqtt.parse(buffer)
  if mqttpkt['error'] then
    return false
  end

  return true
end
core.register_convertes(is_mqtt_connect, is_mqtt_connect)


--[[--
  type: fetch
  purpose: returns any field from the mqtt CONNECT message
  arguments: field name to be retrieved. Most commons are clientid, username, password
  return: string containing the value of the requested field. '-' if can't be found
  configuration example: 
    use_backend b_mosquitto if { lua.get_mqtt_connect_field(clientid) -m beg mosqsub| }
--]]--
local function get_mqtt_connect_field(txn, field)
  if string.len(field) == 0 then
    return '-'
  end

  local buffer = tostring(txn.sc:hex(txn.req:dup()))
  if string.len(buffer) < 8 then
    return false
  end

  local mqttpkt = mqtt.parse(buffer)
  if mqttpkt['error'] then
    return ''
  end

  if mqttpkt[field] ~= nil then
    return mqttpkt[field]
  end

  return '-'
end
core.register_fetches('get_mqtt_connect_field', get_mqtt_connect_field)


--[[--
  type: action
  purpose: execute a custom code with data extracted from mqtt CONNECT message
  arguments: none
  return: nothing (may set variables in haproxy's memory)
  configuration example:
--]]--
local function checkauth(txn)
  local buffer = tostring(txn.sc:hex(txn.req:dup()))
  local mqttpkt = mqtt.parse(buffer)

  if mqttpkt['error'] then
    txn.log(txn, core.info, mqttpkt['errormessage'])
    return
  end

  if debug then
    print(mqttpkt['username'])
    print(mqttpkt['password'])
  end

  -- implement your authentication validation here
end
core.register_action("checkauth", { "tcp-req" }, checkauth)

