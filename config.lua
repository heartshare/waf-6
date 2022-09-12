-- waf配置相关(注意每次修改都要重启nginx以便生效)
-- WafGuard安装目录,修改为实际安装到的目录
baseDir = '/usr/local/nginx/waf/'

local Config = {
    -- 基础配置
    -- 是否开启waf拦截
    enable = true,
    -- 是否开启debug日志
    -- 日志级别,1:攻击日志 2:拦截日志 3:调试日志
    logLevel = 3,
    -- 日志目录,注意需要设置logs所有者为nginx运行用户
    -- 如nginx运行用户为nobody,则命令为chown -R nobody logs
    -- 或者将nginx.conf配置中的user改成对应用户nobody
    logPath = baseDir.."logs/",
    -- 是否开启日志轮询,每天生成日志文件
    logRotate = true,
    -- 是否为代理转发请求,如果为代理则获取readip需要获取header来获取
    isProxy = true,
    -- 模板文件路径
    templatePath = baseDir..'template',

    -- 封禁模块,当黑名单/注入攻击检测/cc防御检测进行封禁会调用相关封禁模块进行封禁
    -- ngx封禁,直接ngx断开与用户的请求,可快速释放资源
    -- exitCode nginx返回错误码,一般为444或者304
    ngxBanModule = { exitCode=444 },
    -- iptables/ipset封禁,ipset为true则用ipset封禁,在封堵大量ip时性能更佳,并且可配置封禁时间,需要安装ipset
    ipBanModule = { ipSet=false },
    -- 网页提示封禁,相对更加友好,但在大量机刷式攻击时效果较差,banReaon为网页提示信息
    htmlBanModule = { banReason="抱歉，您的访问疑似攻击请求，已被系统自动拦截，如为误封请联系客服。" },

    -- 黑白名单相关配置,内容为正则表达式
    -- 配置说明
    -- banAction:指定哪个封禁模块进行封禁
    -- 白名单ip模块
    whiteIpModule = { on=true, rule=baseDir.."rules/whiteIpList.rule" },
    -- 白名单url模块，例如robots.txt为爬虫需要，可配置白名单url
    whiteUrlModule = { on=true, rule=baseDir.."rules/whiteUrlList.rule" },
    -- 白名单域名模块，某些网站如果想绕开waf检测，可直接配置域名白名单
    whiteSiteModule = { on=true, rule=baseDir.."rules/whiteSiteList.rule" },
    -- 黑名单ip模块
    blackIpModule = { on=true, rule=baseDir.."rules/blackIpList.rule", banAction="ban_with_ngx" },
    -- 黑名单url模块，例如网站不提供php则配置php拦截
    blackUrlModule = { on=true, rule=baseDir.."rules/blackUrlList.rule", banAction="ban_with_ngx" },
    -- 黑名单域名模块，某些网站如果被刷的严重要人工处理，可直接配置域名黑名单
    blackSiteModule = { on=true, rule=baseDir.."rules/blackSiteList.rule", banAction="ban_with_ip" },
    -- 黑名单ip模块
    blackUaModule = { on=true, rule=baseDir.."rules/blackUaList.rule", banAction="ban_with_ngx" },

    -- 注入拦截相关配置,内容为正则表达式
    -- on:模块是否开启
    -- postOn:是否开启post参数检测(对性能会有些许影响),默认只是url参数检测
    -- injectTime,injectCnt:(ip+域名)漏洞试探在injectTime秒允许试探injectCnt次(-1为不检查次数),
    -- 超过配置次数则用封禁模块进行封禁
    -- banAction:指定哪个封禁模块进行封禁
    -- overAction:当漏洞试探超过injectCnt时指定哪个封禁模块进行封禁
    antiInjectModule = { on=true, postOn=true, injectTime=60, injectCnt=60, banAction="ban_with_html", overAction="ban_with_ngx" },
    -- sql注入拦截模块
    sqlInjectModule = { rule=baseDir.."rules/sqlInjectList.rule" },
    -- xss注入拦截模块
    xssInjectModule = { rule=baseDir.."rules/xssInjectList.rule" },
    -- cmd注入拦截模块
    cmdInjectModule = { rule=baseDir.."rules/cmdInjectList.rule" },
    -- referer注入拦截模块
    refInjectModule = { rule=baseDir.."rules/refInjectList.rule" },

    -- cc防御相关配置
    -- 总共有三大防御模块,分别为域名请求防御模块、ip请求防御模块、ip+域名请求防御模块
    -- 域名限制模块,一个域名只能在指定时间内请求一定次数,以防止被人肉刷死,最严的防御,触发限制之后所有请求该域名的ip都被限制
    -- on:模块是否开启
    -- limitReqs,limitTime:在limitTime秒内允许请求的最大次数limitReqs,如默认的是在60s内最大允许请求300次。
    -- banTime:触发限制规则时该域名被ban的时间,单位秒
    -- banAction:指定哪个封禁模块进行封禁
    -- 1、TODO新增conn并发请求限制,超过一定阀值ngx.sleep,再超过ban
    -- 2、TODO新增log来统计限速模块,新增流量限速模块,超过一定阀值ngx.sleep,再超过ban
    limitDomainModule = { on=true, limitReqs=600000, limitTime=60, banTime=60, banAction="ban_with_ip" },
    -- ip请求限制模块,一个ip只能在指定时间内请求一定次数,触发限制之后所有请求该ip的请求都被限制
    -- on:模块是否开启
    -- limitReqs,limitTime:在limitTime秒内允许请求的最大次数limitReqs,如默认的是在60s内每个ip最大允许请求300次。
    -- banTime:触发限制规则时该ip被ban的时间,单位秒
    -- banAction:指定哪个封禁模块进行封禁
    limitIpModule = { on=true, limitReqs=600000, limitTime=60, banTime=60, banAction="ban_with_ngx" },
    -- cc防御模块,由下面各个模块配合防御
    -- on:模块是否开启
    -- limitTime:在limitTime秒内统计请求次数,如默认在60秒内统计(ip+域名)的请求次数
    -- validCnt:防御验证失败的次数,超过配置次数则ban
    -- validTime:防御模块会发送验证信息给客户端,如果访客在validTime时间内没有返回正确的结果,则会被ban
    -- passTime:防御模块验证通过后的放行时间,单位秒
    -- banTime:触发限制规则时该域名被ban的时间,单位秒
    -- dynamic:是否动态生成cookie key,如果false,修改手动修改下面的key
    -- cookieKey:用于生成cookie的key,如果上面的dynamic为true,就不需要修改
    -- limitAction:默认由哪个防御模块进行第一层拦截
    -- banAction:指定哪个封禁模块进行封禁
    limitReqModule = { on=true, dynamic=true, cookieKey='_limit_key_', limitTime=120, validCnt=3, validTime=60, passTime=60, banTime=60, limitAction="limitCookieModule", banAction="ban_with_html" },
    -- cookie防御模块,发送cookie验证模块,建立在limitReqModule防御模块开启的情况下
    -- 此模块会向访客发送cookie,然后等待访客返回正确的cookie,此模块利用cc控制端无法支持cookie的特点,来识别cc攻击
    -- limitReqs:在limitTime秒内允许请求的最大次数limitReqs,如默认的是在60s内最大允许请求300次
    -- nextAction:该拦截通过之后由哪个模块进行下一层拦截,采用多级防御,避免该层拦截被破解导致防御失效,如果不需要下层拦截则不配置
    limitCookieModule = { limitReqs=1000, nextAction="limitJsJumpModule" },
    -- js防御模块,发送js跳转代码模块,建立在limitReqModule防御模块开启的情况下
    -- 此模块利用cc控制端无法解析js跳转的特点,来识别是否为正常用户
    -- limitReqs:在limitTime秒内允许请求的最大次数limitReqs,如默认的是在60s内最大允许请求300次
    -- nextAction:该拦截通过之后由哪个模块进行下一层拦截,采用多级防御,避免该层拦截被破解导致防御失效,如果不需要下层拦截则不配置
    limitJsJumpModule = { limitReqs=5000, nextAction="limitCaptchaModule" },
    -- 验证码防御模块,发送图形验证码让用户输入,为最后一层防御,建立在limitReqModule防御模块开启的情况下
    -- limitReqs:在limitTime秒内允许请求的最大次数limitReqs,如默认的是在60s内最大允许请求300次
    -- imgReqs:刷验证码的次数,只能让客户端更换验证码一定次数,超过也直接ban
    limitCaptchaModule = { limitReqs=100000, imgReqs=100 },
}

return Config