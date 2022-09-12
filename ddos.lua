local Util = require("util")
local Ddos = {}

function Ddos:getLimitReqPhase(limitReqAction)
    if limitReqAction then
        if limitReqAction == "limitCookieModule" then
            return _conf.limitReqPhaseCookie
        elseif limitReqAction == "limitJsJumpModule" then
            return _conf.limitReqPhaseJsJump
        elseif limitReqAction == "limitCaptchaModule" then
            return _conf.limitReqPhaseCaptcha
        end
    end

    return _conf.limitReqPhasePass
end

-- cookie防御模块
function Ddos:limitCookieModule(ipDomain, cookie, req, ip, uri, validPhase, validFailCnt)
    -- 进入防御检测阶段，校验客户端是有传递cookie值
    if validPhase == _conf.limitChkPhaseCookie then
        local uid = cookie:get("_uid_")
        if uid then
            local ipCookie = ip..uid
            local cookieVal = _conf.limitStatDict:get(ipCookie)
            if cookieVal then
                -- 无论成不成功,先清除验证数据,失败后会重新生成验证数据
                _conf.limitStatDict:delete(ipCookie)
                -- 将客户传递过来的cookie和服务器端保存的cookie做匹配对比
                local ucookie = cookie:get(uid)
                if tostring(cookieVal) == ucookie then
                    Util:logDebug("[limitCookieModule]", "Valid Cookie", ip, uri)
                    -- 客户端带正确的cookie过来,验证通过,开始下一模块的验证,如果有配置的话
                    local nextPhase = self:getLimitReqPhase(_conf.limitCookieNextAction)
                    _conf.limitStatDict:set(ipDomain, nextPhase, _conf.limitReqPassTime)
                    return true
                end
            end
        end

        -- 验证不通过,验证失败+1,重发cookie再次验证
        Util:logWaf("[limitCookieModule]", "Invalid Cookie", ip, uri)
        validFailCnt = validFailCnt + 1
        _conf.limitStatDict:set(ipDomain, validPhase, _conf.limitReqValidTime, validFailCnt)
        self:limitCookieOutput(cookie, ip)
        return false
    end

    -- 判断客户端请求是否超过该防御模块配置的请求阀值
    if req > _conf.limitCookieReqs then
        Util:logAttack("[limitCookieModule]", ip, ip, uri)
        _conf.limitStatDict:set(ipDomain, _conf.limitChkPhaseCookie, _conf.limitReqValidTime, validFailCnt)
        self:limitCookieOutput(cookie, ip)

        return false
    end

    return false
end

-- cookie防御模块,发送cookie验证
function Ddos:limitCookieOutput(cookie, ip)
    local cookieKey = _conf.limitReqCookieKey
    if _conf.limitReqDynamic then
        cookieKey = self:genCookieKey()
    end
    local cookieVal = self:genCookieVal()
    -- 即使是同一个ip,也让每个客户端都生成唯一的cookie id,
    -- 避免同一公司ip的用户如果交叉请求导致cookie失效被ban
    local ipCookie = ip..cookieKey
    _conf.limitStatDict:set(ipCookie, cookieVal, _conf.limitReqValidTime)
    --发送cookie
    cookie:set({
        key = "_uid_", value = cookieKey
    })
    cookie:set({
        key = cookieKey, value = cookieVal
    })
end

-- js跳转防御模块
function Ddos:limitJsJumpModule(ipDomain, cookie, req, ip, uri, validPhase, validFailCnt)
    -- 进入防御检测阶段，校验客户端是有传递cookie值
    if validPhase == _conf.limitChkPhaseJsJump then
        local uid = cookie:get("_uid_")
        if uid then
            local ipCookie = ip..uid
            local cookieVal = _conf.limitStatDict:get(ipCookie)
            if cookieVal then
                -- 无论成不成功,先清除验证数据,失败后会重新生成验证数据
                _conf.limitStatDict:delete(ipCookie)
                local ucookie = cookie:get(uid)
                -- 将客户传递过来的cookie和服务器端保存的cookie做匹配对比
                if tostring(cookieVal) == ucookie then
                    Util:logDebug("[limitJsJumpModule]", "Valid Js Jump Cookie", ip, uri)
                    -- 客户端带正确的cookie过来,验证通过,开始下一模块的验证,如果有配置的话
                    local nextPhase = self:getLimitReqPhase(_conf.limitJsJumpNextAction)
                    _conf.limitStatDict:set(ipDomain, nextPhase, _conf.limitReqPassTime)
                    return true
                end
            end
        end

        -- 验证不通过,验证失败+1,重发cookie再次验证
        Util:logDebug("[limitJsJumpModule]", "Invalid Js Jump Cookie", ip, uri)
        validFailCnt = validFailCnt + 1
        _conf.limitStatDict:set(ipDomain, validPhase, _conf.limitReqValidTime, validFailCnt)
        self:limitJsJumpOutput(ip, uri)
        return false
    end

    -- 判断客户端请求是否超过该防御模块配置的请求阀值
    if req > _conf.limitJsJumpReqs then
        Util:logAttack("[limitJsJumpModule]", ip, ip, uri)
        _conf.limitStatDict:set(ipDomain, _conf.limitChkPhaseJsJump, _conf.limitReqValidTime, validFailCnt)
        self:limitJsJumpOutput(ip, uri)

        return false
    end

    return false
end

-- 验证码防御模块
function Ddos:limitCaptchaModule(ipDomain, cookie, req, ip, uri, validPhase, validFailCnt)
    -- 进入防御检测阶段，校验客户端是有传递cookie值
    if validPhase == _conf.limitChkPhaseCaptcha then
        -- img请求
        local imgUid = _rulematch(uri, "^/output/(.*)/.*img$", "jo")
        if imgUid and imgUid[1] then
            local uid = imgUid[1]
            if not uid then
                Util:logWaf("[limitCaptchaModule]", "Invalid Img Request", ip, uri)
                BanAction:banAction(_conf.limitReqBanAction, ip)
            end

            -- 获取验证码请求次数
            local ipCookie = ip..uid
            local cookieVal, imgReqs = _conf.limitStatDict:get(ipCookie)
            if imgReqs then
                imgReqs = imgReqs + 1
            else
                imgReqs = 1
            end
            -- 超过验证码请求次数也认为是恶意刷，直接ban
            if _conf.limitCaptchaImgReqs > 0 and imgReqs > _conf.limitCaptchaImgReqs then
                Util:logWaf("[limitCaptchaModule]", "Captcha Img Reqs Over Limit", ip, uri)
                BanAction:banAction(_conf.limitReqBanAction, ip)
            end

            self:captchaImgOutput(ipCookie, ip, uid, imgReqs);
            return true
        end

        local uid = cookie:get("_uid_")
        if uid then
            local ipCookie = ip..uid
            local cookieVal = _conf.limitStatDict:get(ipCookie)

            if cookieVal then
                -- 无论成不成功,先清除验证数据,失败后会重新生成验证数据
                _conf.limitStatDict:delete(ipCookie)
                local ucookie = cookie:get(uid)
                -- 将客户传递过来的cookie和服务器端保存的cookie做匹配对比
                if tostring(cookieVal) == ucookie then
                    Util:logDebug("[limitCaptchaModule]", "Valid Captcha Cookie", ip, uri)
                    -- 客户端带正确的cookie过来,验证通过,开始下一模块的验证,如果有配置的话
                    local nextPhase = self:getLimitReqPhase(_conf.limitCaptchaNextAction)
                    _conf.limitStatDict:set(ipDomain, nextPhase, _conf.limitReqPassTime)
                    return true
                end
            end
        end

        -- 验证不通过,验证失败+1,重发cookie再次验证
        Util:logDebug("[limitCaptchaModule]", "Invalid Captcha Cookie", ip, uri)
        validFailCnt = validFailCnt + 1
        _conf.limitStatDict:set(ipDomain, validPhase, _conf.limitReqValidTime, validFailCnt)
        self:limitCaptchaOutput(ip, uri, validFailCnt)
        return false
    end

    -- 判断客户端请求是否超过该防御模块配置的请求阀值
    if req > _conf.limitCaptchaReqs then
        Util:logAttack("[limitCaptchaModule]", ip, ip, uri)
        _conf.limitStatDict:set(ipDomain, _conf.limitChkPhaseCaptcha, _conf.limitReqValidTime, validFailCnt)
        self:limitCaptchaOutput(ip, uri, validFailCnt)

        return false
    end

    return false
end

-- js跳转防御模块,发送一段js跳转代码让客户端跳转到真正的网站
function Ddos:limitJsJumpOutput(ip, uri)
    local cookieKey = _conf.limitReqCookieKey
    if _conf.limitReqDynamic then
        cookieKey = self:genCookieKey()
    end
    local cookieVal = self:genCookieVal()
    -- 即使是同一个ip,也让每个客户端都生成唯一的cookie id,
    -- 避免同一公司ip的用户如果交叉请求导致cookie失效被ban
    local ipCookie = ip..cookieKey
    _conf.limitStatDict:set(ipCookie, cookieVal, _conf.limitReqValidTime)

    local locationHref = ngx.var.scheme.."://"..ngx.var.host..uri
    local arguments = {}
    arguments["#jumpHost#"] = locationHref
    arguments["#uidKey#"] = cookieKey
    arguments["#uidVal#"] = cookieVal
    Util:printTemplate(_conf.templatePath.."/ccjs.html", "text/html", 200, arguments)
end

-- 验证码图片输出
function Ddos:captchaImgOutput(ipCookie, ip, uid, imgReqs)
    -- 生成验证码数字并设置相关信息到字典内存中等待客户输入验证码进行验证
    local dict = {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3','4','5','6','7','8','9'}
    local stringMark = ""
    math.randomseed(ngx.now()) --随机数种子，确保每次验证码真正随机
    for i = 1,6 do
        stringMark = stringMark..dict[math.random(1,36)]
    end
    local cookieVal = stringMark
    local ipCookie = ip..uid
    _conf.limitStatDict:set(ipCookie, cookieVal, _conf.limitReqValidTime, imgReqs)

    local xsize = 80
    local ysize = 30
    local gd = require('gd')
    local im = gd.createTrueColor(xsize,ysize)
    local black = im:colorAllocate(0,0,0)
    local grey = im:colorAllocate(216,235,238)
    local color = {}
    for c=1,100 do
        color[c] = im:colorAllocate(math.random(100),math.random(100),math.random(100))
    end
    local x,y = im:sizeXY()
    im:filledRectangle(0,0,x,y,grey)
    -- gd.useFontConfig(true)
    im:string(gd.FONT_LARGE, 16, 8, stringMark, black)
    for j=1,math.random(3) do
        im:line(math.random(xsize),math.random(ysize),math.random(xsize),math.random(ysize),color[math.random(100)])
    end
    for p=1,20 do
        im:setPixel(math.random(xsize),math.random(ysize),color[math.random(100)])
    end
    local fp = im:pngStr(75)
    ngx.header.content_type = "image/png"
    ngx.say(fp)
    ngx.exit(200)
end

-- 验证码防御模块,生成验证码让客户端输入验证
function Ddos:limitCaptchaOutput(ip, uri, validFailCnt)
    local cookieUsrId = self:genCookieKey()
    local ipCookie = ip..cookieUsrId
    local cookieVal = ipCookie
    _conf.limitStatDict:set(ipCookie, cookieVal, _conf.limitReqValidTime, 0)
    local locationHref = ngx.var.scheme.."://"..ngx.var.host..uri
    local imgSrc = "/output/"..cookieUsrId.."/"..tostring(math.random(1000000))..".img"
    local arguments = {}
    arguments["#cookieUsrId#"] = cookieUsrId
    arguments["#imgSrc#"] = imgSrc
    arguments["#locationHref#"] = locationHref
    arguments["#retryCount#"] = _conf.limitReqValidCnt - validFailCnt
    Util:printTemplate(_conf.templatePath.."/captcha.html", "text/html", 200, arguments)
end

function Ddos:getLimitReqModule(validPhase)
    if validPhase then
        if validPhase == _conf.limitReqPhaseCookie 
            or validPhase == _conf.limitChkPhaseCookie then
            return "limitCookieModule"
        elseif validPhase == _conf.limitReqPhaseJsJump 
            or validPhase == _conf.limitChkPhaseJsJump then
            return "limitJsJumpModule"
        elseif validPhase == _conf.limitReqPhaseCaptcha 
            or validPhase == _conf.limitChkPhaseCaptcha then
            return "limitCaptchaModule"
        end
    end

    return _conf.limitReqAction
end

-- 随机生成cookie键用于验证
function Ddos:genCookieKey()
    math.randomseed(os.time()) --随机种子
    local r1 = math.random(1,62) --生成1-62之间的随机数
    local r2 = math.random(1,62) --生成1-62之间的随机数
    local r3 = math.random(1,62) --生成1-62之间的随机数
    local r4 = math.random(1,62) --生成1-62之间的随机数

    return "_u"..r1..r2..r3..r4.."_"
end

-- 随机生成cookie值用于验证
function Ddos:genCookieVal()
    return tostring(os.time())
end

return Ddos
