local Util = {}

-- debug日志
function Util:logDebug(method, data, ip, url)
  if _conf.debugLog then
      Util:log(method, data, ip, url, "[DEBUG]")
  end
end

-- 拦截日志
function Util:logWaf(method, data, ip, url)
  if _conf.wafLog then
      Util:log(method, data, ip, url, "[WAF]")
  end
end

-- 攻击日志
function Util:logAttack(method, data, ip, url)
  if _conf.attackLog then
      Util:log(method, data, ip, url, "[ATTACK]")
  end
end

-- 日志
function Util:log(method, data, ip, url, level)
  local cjson = require("cjson")
  local logJson = {
      time = os.date('%Y-%m-%d %H:%M:%S'),
      method = method,
      data = data,
      ip = ip,
      leve = level,
      url = url,
      host = ngx.var.host,
      -- ua = ngx.var.http_user_agent,
  }
  local logContent = cjson.encode(logJson)

  local filename = _conf.logPath.."/waf.log"
  if _conf.logRotate then
      local date = os.date("%Y%m%d")
      filename = _conf.logPath.."/waf-"..date..".log"
  end
  local file = io.open(filename, "a+")
  file:write(logContent.."\n")
  file:flush()
  file:close()
end

-- 获取客户端ip
function Util:getRealIp(headers)
  local realIp = ""

  if _conf.isProxy then
      realIp = headers["X_Real_Ip"]
      if realIp then
          if type(realIp) == "table" then
              realIp = realIp[1]
          end
          return realIp
      end

      realIp = headers["X_Forwarded_For"]
      if realIp then
          if type(realIp) == "table" then
              realIp = realIp[1]
          end
          return realIp
      end
  end

  realIp = ngx.var.remote_addr
  return realIp
end

-- 读取文件
function Util:readFile(fileName)
    local file = io.open(fileName, "r")
    local content = file:read("*a")
    file:close()
    return content
end

-- 输出模板文件内容
function Util:printTemplate(fileName, contentType, httpCode, arguments)
    local content = self:readFile(fileName)
    if contentType then
        ngx.header.content_type = contentType
    end
    if arguments then
      for k, v in pairs(arguments) do
          content = ngx.re.gsub(tostring(content), tostring(k), tostring(v))
      end
    end
    ngx.status = httpCode or 200
    ngx.say(content)
    ngx.exit(ngx.HTTP_OK)
end

return Util
