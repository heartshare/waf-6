local Config = require("config")

-- 解析文件到正则字符串函数
local function parseRuleFile(isModuleOn, filePath)
    local list = ''
    if isModuleOn then
        local rfile = io.open(filePath, 'r')
        for line in rfile:lines() do
            if not (string.match(line, "^ *$")) then
                list = list.."|"..line
            end
        end
        list = string.gsub(list,"^%|",'')
        rfile:close()
    end
    return list
end

-- 是否开启调试日志
local function isDebugLog(logLevel)
    return logLevel >= 3
end

-- 是否开启拦截日志
local function isWafLog(logLevel)
    return logLevel >= 2
end

-- 是否开启攻击日志
local function isAttackLog(logLevel)
    return logLevel >= 1
end

-- 注意低版本nginx是用ngx.re.match，性能较低
-- local rulematch = ngx.re.find
_rulematch = ngx.re.match
-- 全局配置
_conf = {
    -- 基础设置
    isWafEnable = Config.enable,
    debugLog = isDebugLog(Config.logLevel),
    wafLog = isDebugLog(Config.logLevel),
    attackLog = isAttackLog(Config.logLevel),
    logPath = Config.logPath,
    logRotate = Config.logRotate,
    isProxy = Config.isProxy,
    templatePath = Config.templatePath,

    -- 封禁模块相关配置
    ngxBanModuleExitCode = Config.ngxBanModule.exitCode,
    ipBanModuleIpSet = Config.ipBanModule.ipSet,
    htmlBanModuleBanReason = Config.htmlBanModule.banReason,

    -- 白名单相关配置
    whiteIpModulesIsOn = Config.whiteIpModule.on,
    whiteIpList = parseRuleFile(Config.whiteIpModule.on, Config.whiteIpModule.rule),
    whiteUrlModulesIsOn = Config.whiteUrlModule.on,
    whiteUrlList = parseRuleFile(Config.whiteUrlModule.on, Config.whiteUrlModule.rule),
    whiteSiteModulesIsOn = Config.whiteSiteModule.on,
    whiteSiteList = parseRuleFile(Config.whiteSiteModule.on, Config.whiteSiteModule.rule),

    -- 黑名单相关配置
    blackIpModulesIsOn = Config.blackIpModule.on,
    blackIpList = parseRuleFile(Config.blackIpModule.on, Config.blackIpModule.rule),
    blackIpBanAction = Config.blackIpModule.banAction,
    blackUrlModulesIsOn = Config.blackUrlModule.on,
    blackUrlList = parseRuleFile(Config.blackUrlModule.on, Config.blackUrlModule.rule),
    blackUrlBanAction = Config.blackUrlModule.banAction,
    blackSiteModulesIsOn = Config.blackSiteModule.on,
    blackSiteList = parseRuleFile(Config.blackSiteModule.on, Config.blackSiteModule.rule),
    blackSiteBanAction = Config.blackSiteModule.banAction,
    blackUaModulesIsOn = Config.blackUaModule.on,
    blackUaList = parseRuleFile(Config.blackUaModule.on, Config.blackUaModule.rule),
    blackUaBanAction = Config.blackUaModule.banAction,

    -- 注入防御相关设置
    -- 注入状态缓存,用于记录请求过程中的注入防御状态
    injectStatDict = ngx.shared.inject_stat_dict,
    antiInjectModuleIsOn = Config.antiInjectModule.on,
    antiInjectBanAction = Config.antiInjectModule.banAction,
    antiInjectOverAction = Config.antiInjectModule.overAction,
    antiInjectPostOn = Config.antiInjectModule.postOn,
    antiInjectTime = Config.antiInjectModule.injectTime,
    antiInjectCnt = Config.antiInjectModule.injectCnt,
    sqlInjectList = parseRuleFile(Config.antiInjectModule.on, Config.sqlInjectModule.rule),
    xssInjectList = parseRuleFile(Config.antiInjectModule.on, Config.xssInjectModule.rule),
    cmdInjectList = parseRuleFile(Config.antiInjectModule.on, Config.cmdInjectModule.rule),
    refInjectList = parseRuleFile(Config.antiInjectModule.on, Config.refInjectModule.rule),

    -- cc防御相关设置
    -- cc请求次数缓存,用于记录(域名/ip+域名)访问次数
    limitReqDict = ngx.shared.limit_reqs_dict,
    -- cc防御状态缓存,用于记录请求过程中的cc防御状态
    limitStatDict = ngx.shared.limit_stat_dict,
    -- 域名限制模块相关配置
    limitDomainModuleIsOn = Config.limitDomainModule.on,
    limitDomainBanAction = Config.limitDomainModule.banAction,
    limitDomainReqs = Config.limitDomainModule.limitReqs,
    limitDomainTime = Config.limitDomainModule.limitTime,
    limitDomainBanTime = Config.limitDomainModule.banTime,
    -- ip请求限制模块相关配置
    limitIpModuleIsOn = Config.limitIpModule.on,
    limitIpBanAction = Config.limitIpModule.banAction,
    limitIpReqs = Config.limitIpModule.limitReqs,
    limitIpTime = Config.limitIpModule.limitTime,
    limitIpBanTime = Config.limitIpModule.banTime,
    -- cc防御模块相关配置
    limitReqModuleIsOn = Config.limitReqModule.on,
    limitReqBanAction = Config.limitReqModule.banAction,
    limitReqTime = Config.limitReqModule.limitTime,
    limitReqDynamic = Config.limitReqModule.dynamic,
    limitReqCookieKey = Config.limitReqModule.cookieKey,
    limitReqValidTime = Config.limitReqModule.validTime,
    limitReqPassTime = Config.limitReqModule.passTime,
    limitReqBanTime = Config.limitReqModule.banTime,
    limitReqValidCnt = Config.limitReqModule.validCnt,
    limitReqAction = Config.limitReqModule.limitAction,
    limitCookieReqs = Config.limitCookieModule.limitReqs,
    limitCookieNextAction = Config.limitCookieModule.nextAction,
    limitJsJumpReqs = Config.limitJsJumpModule.limitReqs,
    limitJsJumpNextAction = Config.limitJsJumpModule.nextAction,
    limitCaptchaReqs = Config.limitCaptchaModule.limitReqs,
    limitCaptchaNextAction = Config.limitCaptchaModule.nextAction,
    limitCaptchaImgReqs = Config.limitCaptchaModule.imgReqs,
    -- cc防御各阶段维护
    limitReqPhaseBan     = 1, -- cc防御是否已经封禁该ip请求
    limitReqPhasePass    = 2, -- cc防御验证通过
    limitReqPhaseCookie  = 3, -- cc防御cookie防御阶段
    limitChkPhaseCookie  = 4, -- cc防御cookie防御验证阶段
    limitReqPhaseJsJump  = 5, -- cc防御js防御阶段
    limitChkPhaseJsJump  = 6, -- cc防御js防御验证阶段
    limitReqPhaseCaptcha = 7, -- cc防御验证码防御阶段
    limitChkPhaseCaptcha = 8, -- cc防御验证码防御验证阶段
}
-- 准备对应的环境
local file, err = io.open(_conf.logPath)
if (file == nil) then
    os.execute("mkdir -p ".._conf.logPath)
end
