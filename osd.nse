local nmap = require "nmap"
description = [[
Detects the operating system of a host ]]

categories = {"discovery", "safe"}

portrule = function() return true end

action = function(host)
  local cmd = ("/usr/bin/nmap -O -oG - %s"):format(host.ip)
  local handle = io.popen(cmd)
  local output = handle:read("*all")
  handle:close()
  local os_info = output:match("OS:%s(.+)")
  return os_info and ("The OS is %s"):format(os_info:match("%S+")) or nil
end
