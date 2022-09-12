local Util = require("util")
local BanAction = require("ban")
local Ddos = require("ddos")
local Waf = {}

-- ip白名单模块
function Waf:ipInWhiteList(ip, uri)
    -- 判断是否开启ip白名单模块
    if _conf.whiteIpModulesIsOn then
        -- 匹配白名单列表
        if _conf.whiteIpList ~= "" and _rulematch(ip, _conf.whiteIpList, "jo") then
            Util:logDebug("[ipInWhiteList]", ip, ip, uri)
            return true
        else
            return false
        end
    end
end

-- ip黑名单模块
function Waf:ipInBlackList(ip, uri)
    -- 判断是否开启ip黑名单模块
    if _conf.blackIpModulesIsOn then
        -- 匹配黑名单列表
        if _conf.blackIpList ~= "" and _rulematch(ip, _conf.blackIpList, "jo") then
            Util:logWaf("[ipInBlackList]", ip, ip, uri)
            BanAction:banAction(_conf.blackIpBanAction, ip)
            return true
        else
            return false
        end
    end
end

-- url白名单模块
function Waf:urlInWhiteList(ip, uri)
    -- 判断是否开启url白名单模块
    if _conf.whiteUrlModulesIsOn then
        -- 匹配白名单列表
        if _conf.whiteUrlList ~= "" and _rulematch(uri, _conf.whiteUrlList, "joi") then
            Util:logDebug("[urlInWhiteList]", uri, ip, uri)
            return true
        else
            return false
        end
    end
end

-- url黑名单模块
function Waf:urlInBlackList(ip, uri)
    -- 判断是否开启url黑名单模块
    if _conf.blackUrlModulesIsOn then
        -- 匹配黑名单列表
        if  _conf.blackUrlList ~= "" and _rulematch(uri, _conf.blackUrlList, "joi") then
            Util:logWaf("[urlInBlackList]", uri, ip, uri)
            BanAction:banAction(_conf.blackUrlBanAction, ip)
            return true
        else
            return false
        end
    end
end

-- 域名白名单模块
function Waf:siteInWhiteList(ip, uri)
    -- 判断是否开启域名白名单模块
    if _conf.whiteSiteModulesIsOn then
        -- 匹配白名单列表
        local site = ngx.var.host
        if _conf.whiteSiteList ~= "" and _rulematch(site, _conf.whiteSiteList, "joi") then
            Util:logDebug("[siteInWhiteList]", site, ip, uri)
            return true
        else
            return false
        end
    end
end

-- 域名黑名单模块
function Waf:siteInBlackList(ip, uri)
    -- 判断是否开启域名黑名单模块
    if _conf.blackSiteModulesIsOn then
        -- 匹配黑名单列表
        local site = ngx.var.host
        if  _conf.blackSiteList ~= "" and _rulematch(site, _conf.blackSiteList, "joi") then
            Util:logWaf("[siteInBlackList]", site, ip, uri)
            BanAction:banAction(_conf.blackSiteBanAction, ip)
            return true
        else
            return false
        end
    end
end

-- ua黑名单模块
function Waf:uaInBlackList(ip, uri)
    -- 判断是否开启ua黑名单模块
    if _conf.blackUaModulesIsOn then
        -- 匹配黑名单列表
        local ua = ngx.var.http_user_agent
        if _conf.blackUaList ~= "" and _rulematch(ua, _conf.blackUaList, "joi") then
            Util:logWaf("[uaInBlackList]", ua, ip, uri)
            BanAction:banAction(_conf.blackUaBanAction, ip)
            return true
        else
            return false
        end
    end
end

-- sql注入防御模块
function Waf:sqlInjectList(ip, uri, postArgs)
    -- 判断是否开启注入防御模块
    if _conf.antiInjectModuleIsOn then
        local matched, args = self:isInjectListMatched(uri, _conf.sqlInjectList, postArgs)
        if matched then
            local banAction = _conf.antiInjectBanAction
            -- 如果连续注入试探超配置限制则调用封禁模块进行拦截封禁
            if _conf.antiInjectCnt > 0 then
                -- 获取该ip已经尝试深入注入了多少次
                local ipDomain = ip..ngx.var.host
                local injectCnt = _conf.injectStatDict:get(ipDomain)
                if injectCnt then
                    injectCnt = injectCnt + 1
                else
                    injectCnt = 1
                end
                _conf.injectStatDict:set(ipDomain, injectCnt, _conf.antiInjectTime)
                -- 注入超过限制次数，iptables ban
                if injectCnt > _conf.antiInjectCnt then
                  banAction = _conf.antiInjectOverAction
                end
            end
            Util:logWaf("[sqlInjectList]", args, ip, uri)
            BanAction:banAction(banAction, ip)
            return true
        end

        return false
    end
end

-- xss注入防御模块
function Waf:xssInjectList(ip, uri, postArgs)
    -- 判断是否开启注入防御模块
    if _conf.antiInjectModuleIsOn then
        local matched, args = self:isInjectListMatched(uri, _conf.xssInjectList, postArgs)
        if matched then
            local banAction = _conf.antiInjectBanAction
            -- 如果连续注入试探超配置限制则调用封禁模块进行拦截封禁
            if _conf.antiInjectCnt > 0 then
                -- 获取该ip已经尝试深入注入了多少次
                local ipDomain = ip..ngx.var.host
                local injectCnt = _conf.injectStatDict:get(ipDomain)
                if injectCnt then
                    injectCnt = injectCnt + 1
                else
                    injectCnt = 1
                end
                _conf.injectStatDict:set(ipDomain, injectCnt, _conf.antiInjectTime)
                -- 注入超过限制次数，iptables ban
                if injectCnt > _conf.antiInjectCnt then
                    banAction = _conf.antiInjectOverAction
                end
            end
            Util:logWaf("[xssInjectList]", args, ip, uri)
            BanAction:banAction(banAction, ip)
            return true
        end

        return false
    end
end

-- cmd注入防御模块
function Waf:cmdInjectList(ip, uri, postArgs)
    -- 判断是否开启注入防御模块
    if _conf.antiInjectModuleIsOn then
        local matched, args = self:isInjectListMatched(uri, _conf.cmdInjectList, postArgs)
        if matched then
            local banAction = _conf.antiInjectBanAction
            -- 如果连续注入试探超配置限制则调用封禁模块进行拦截封禁
            if _conf.antiInjectCnt > 0 then
                -- 获取该ip已经尝试深入注入了多少次
                local ipDomain = ip..ngx.var.host
                local injectCnt = _conf.injectStatDict:get(ipDomain)
                if injectCnt then
                    injectCnt = injectCnt + 1
                else
                    injectCnt = 1
                end
                _conf.injectStatDict:set(ipDomain, injectCnt, _conf.antiInjectTime)
                -- 注入超过限制次数，iptables ban
                if injectCnt > _conf.antiInjectCnt then
                  banAction = _conf.antiInjectOverAction
                end
            end
            Util:logWaf("[cmdInjectList]", args, ip, uri)
            BanAction:banAction(banAction, ip)
            return true
        end

        return false
    end
end

-- referer注入防御模块
function Waf:refInjectList(ip, uri)
    -- 判断是否开启注入防御模块
    if _conf.antiInjectModuleIsOn then
        local referer = ngx.var.http_referer
        if not referer then
            return false
        end
        local matched, args = self:isInjectListMatched(referer, _conf.refInjectList)
        if matched then
            local banAction = _conf.antiInjectBanAction
            -- 如果连续注入试探超配置限制则调用封禁模块进行拦截封禁
            if _conf.antiInjectCnt > 0 then
                -- 获取该ip已经尝试深入注入了多少次
                local ipDomain = ip..ngx.var.host
                local injectCnt = _conf.injectStatDict:get(ipDomain)
                if injectCnt then
                    injectCnt = injectCnt + 1
                else
                    injectCnt = 1
                end
                _conf.injectStatDict:set(ipDomain, injectCnt, _conf.antiInjectTime)
                -- 注入超过限制次数，iptables ban
                if injectCnt > _conf.antiInjectCnt then
                  banAction = _conf.antiInjectOverAction
                end
            end
            Util:logWaf("[refInjectList]", args, ip, uri)
            BanAction:banAction(banAction, ip)
            return true
        end

        return false
    end
end

-- 注入规则匹配
function Waf:isInjectListMatched(injectCont, injectList, postArgs)
    -- 配置规则文件为空,不进行检测
    if not injectList or injectList == "" then
        return false
    end

    -- 先url匹配注入规则列表
    if _rulematch(injectCont, injectList, "joi") then
        return true, injectCont
    end
    
    -- 再post匹配注入规则列表
    if postArgs then
        local args = nil
        for key, val in pairs(postArgs) do
            if type(val) == "table" then
                if type(val[1]) == "boolean" then
                    return
                end
                args = table.concat(val,", ")
            else
                args = val
            end
            if _rulematch(args, injectList, "joi") then
                return true, args
            end
        end
    end

    return false
end

-- 域名限速模块，核心模块
function Waf:limitDomainModule(ip, uri)
    if _conf.limitDomainModuleIsOn then
        local domain = ngx.var.host
        local domainReq = _conf.limitReqDict:get(domain)
        local domaninIsBan = _conf.limitStatDict:get(domain)
        -- 先统计请求次数
        if domainReq then
            -- 域名请求次数递增
            domainReq = domainReq + 1
            _conf.limitReqDict:incr(domain, 1)
        else
            -- 域名第一次请求
            domainReq = 1
            _conf.limitReqDict:set(domain, 1, _conf.limitDomainTime)
        end
        Util:logDebug("[limitDomainModule]", "DomainReq="..domainReq, ip, uri)

        -- 如果该域名请求已经被拦截,直接退出无需进行下层检测
        if domaninIsBan ~= nil then
            Util:logWaf("[limitDomainModule]", "DomainReq="..domainReq, ip, uri)
            BanAction:banAction(_conf.limitDomainBanAction, ip)
            return true
        end

        -- 检查域名请求是否超过最大请求限制,以防止人肉刷死
        if domainReq > _conf.limitDomainReqs then
            _conf.limitStatDict:set(domain, 1, _conf.limitDomainBanTime)
            Util:logAttack("[limitDomainModule]", "DomainReq="..domainReq, ip, uri)
            BanAction:banAction(_conf.limitDomainBanAction, ip)
            return true
        end

        return false
    end
end

-- ip限速模块，核心模块
function Waf:limitIpModule(ip, uri)
    if _conf.limitIpModuleIsOn then
        local ipReq = _conf.limitReqDict:get(ip)
        local ipIsBan = _conf.limitStatDict:get(ip)
        -- 先统计请求次数
        if ipReq then
            -- ip请求次数递增
            ipReq = ipReq + 1
            _conf.limitReqDict:incr(ip, 1)
        else
            -- ip第一次请求
            ipReq = 1
            _conf.limitReqDict:set(ip, 1, _conf.limitIpTime)
        end
        Util:logDebug("[limitIpModule]", "IpReq="..ipReq, ip, uri)

        -- 如果该ip请求已经被拦截,直接退出无需进行下层检测
        if ipIsBan ~= nil then
            Util:logWaf("[limitIpModule]", "IpReq="..ipReq, ip, uri)
            BanAction:banAction(_conf.limitIpBanAction, ip)
            return true
        end

        -- 检查ip请求是否超过最大请求限制
        if ipReq > _conf.limitIpReqs then
            _conf.limitStatDict:set(ip, 1, _conf.limitIpBanTime)
            Util:logAttack("[limitIpModule]", "IpReq="..ipReq, ip, uri)
            BanAction:banAction(_conf.limitIpBanAction, ip)
            return true
        end

        return false
    end
end

-- cc防御模块，核心模块
function Waf:limitReqModule(ip, uri)
    if _conf.limitReqModuleIsOn then
        local ipDomain = ip..ngx.var.host
        local ipDomainReq = _conf.limitReqDict:get(ipDomain)
        local validPhase, validFailCnt = _conf.limitStatDict:get(ipDomain)
        if not validFailCnt then
            validFailCnt = 0
        end

        local ck = require "cookie"
        local cookie = ck:new()

        -- 先统计请求次数
        if ipDomainReq then
            -- 域名请求次数递增
            ipDomainReq = ipDomainReq + 1
            _conf.limitReqDict:incr(ipDomain, 1)
        else
            -- 域名第一次请求
            ipDomainReq = 1
            _conf.limitReqDict:set(ipDomain, 1, _conf.limitReqTime)
        end
        Util:logDebug("[limitReqModule]", "IpDomainReq="..ipDomainReq, ip, uri)

        -- 该ip已验证通过,放行请求一段时间
        if validPhase == _conf.limitReqPhasePass then
            ngx.var.waf_policy = "pass"
            Util:logDebug("[limitReqModule]", "Pass", ip, uri)
            return false
        end

        -- 如果该ip请求已经被cc防御拦截,直接退出无需进行下层检测
        if validPhase == _conf.limitReqPhaseBan then
            Util:logWaf("[limitReqModule]", "Baned", ip, uri)
            BanAction:banAction(_conf.limitReqBanAction, ip)
            return true
        end

        -- 如果该ip请求拦截验证超过配置失败次数,直接退出无需进行下层检测
        if _conf.limitReqValidCnt and validFailCnt >= _conf.limitReqValidCnt then
            Util:logAttack("[limitReqModule]", "Baned", ip, uri)
            _conf.limitStatDict:set(ipDomain, _conf.limitReqPhaseBan, _conf.limitReqBanTime)
            BanAction:banAction(_conf.limitReqBanAction, ip)
            return true
        end

        -- 根据配置的模块进行防御检测
        local reqModule = Ddos:getLimitReqModule(validPhase)
        if reqModule then
            if reqModule == "limitCookieModule" then
                return Ddos:limitCookieModule(ipDomain, cookie, ipDomainReq, ip, uri, validPhase, validFailCnt)
            elseif reqModule == "limitJsJumpModule" then
                return Ddos:limitJsJumpModule(ipDomain, cookie, ipDomainReq, ip, uri, validPhase, validFailCnt)
            elseif reqModule == "limitCaptchaModule" then
                return Ddos:limitCaptchaModule(ipDomain, cookie, ipDomainReq, ip, uri, validPhase, validFailCnt)
            end
        end

        return false
    end
end

return Waf
