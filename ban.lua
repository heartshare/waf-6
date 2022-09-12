local Util = require("util")
local BanAction = {}

-- 拒绝访问模块动作
function BanAction:banAction(banActionModule, ip)
    ngx.var.waf_policy = banActionModule
    if "ban_with_ngx" == banActionModule then
        self:ngxBanModule()
    elseif "ban_with_ip" == banActionModule then
        self:ipBanModule(ip)
    elseif "ban_with_html" == banActionModule then
        self:htmlBanModule()
    end
end

-- nginx封禁模块动作
function BanAction:ngxBanModule()
    ngx.header.content_type = "text/html"
    ngx.exit(_conf.ngxBanModuleExitCode)
end

-- ip封禁模块动作
function BanAction:ipBanModule(ip)
    if _conf.ipBanModuleIpSet then
        local cmd = "/sbin/ipset add wafban "..ip
        os.execute(cmd)
    else
        local cmd = "/sbin/iptables -A INPUT -p tcp -s "..ip.." --dport 80 -j DROP"
        os.execute(cmd)
    end
    -- nginx444直接断开请求
    ngx.header.content_type = "text/html"
    ngx.exit(444)
end

-- html封禁模块动作
function BanAction:htmlBanModule()
    local arguments = {}
    arguments["#banReason#"] = _conf.htmlBanModuleBanReason
    Util:printTemplate(_conf.templatePath.."/xssban.html", "text/html", 200, arguments)
end

return BanAction
