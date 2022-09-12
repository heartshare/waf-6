local Util = require("util")
local Waf = require("waf")
local headers = ngx.req.get_headers()
local ip = Util:getRealIp(headers)
local uri = ngx.unescape_uri(ngx.var.request_uri)

-- waf拦截入口
local function waf_main()
    -- 判断是否开启waf请求拦截
    if not _conf.isWafEnable then
      return
    end
    -- 白单相关模块
    -- 检查ip白名单
    if Waf:ipInWhiteList(ip, uri) then
        return
    end
    -- 检查url白名单
    if Waf:urlInWhiteList(ip, uri) then
        return
    end
    -- 检查域名白名单
    if Waf:siteInWhiteList(ip, uri) then
        return
    end

    -- cc防御相关模块
    -- 域名限速检测
    if Waf:limitDomainModule(ip, uri) then
        return
    end
    -- ip限速检测
    if Waf:limitIpModule(ip, uri) then
        return
    end
    -- cc防御检测
    if Waf:limitReqModule(ip, uri) then
        return
    end

    -- 黑名单相关模块
    -- 检查ip黑名单
    if Waf:ipInBlackList(ip, uri) then
        return
    end
    -- 检查url黑名单
    if Waf:urlInBlackList(ip, uri) then
        return
    end
    -- 检查域名黑名单
    if Waf:siteInBlackList(ip, uri) then
        return
    end
    -- 检查ua黑名单
    if Waf:uaInBlackList(ip, uri) then
        return
    end

    -- 注入防御相关模块
    -- 判断是否开启post参数检查，如果有开启则获取post参数
    local postArgs = nil
    if _conf.antiInjectPostOn and ngx.var.request_method == "POST" then
        ngx.req.read_body()
        postArgs = ngx.req.get_post_args()
    end
    -- sql注入安全防御
    if Waf:sqlInjectList(ip, uri, postArgs) then
        return
    end
    -- xss注入安全防御
    if Waf:xssInjectList(ip, uri, postArgs) then
        return
    end
    -- cmd注入安全防御
    if Waf:cmdInjectList(ip, uri, postArgs) then
        return
    end
    -- ref注入安全防御
    if Waf:refInjectList(ip, uri) then
        return
    end
end

waf_main()