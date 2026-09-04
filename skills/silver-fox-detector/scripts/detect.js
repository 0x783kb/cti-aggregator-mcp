#!/usr/bin/env node
/**
 * Silver Fox Detector · 银狐仿冒站点检测引擎
 * 版本: V1.2（2026-09-04，渐进式披露重构，检测逻辑与 V1.1 完全一致）
 *
 * 九条规则：域名仿冒 60 / 压缩包下载 40 / ICP 30 / 链接分析 70 / 代码工程化 60 /
 *          域名年龄 60 / 老域补偿 -20 / 跨域下载 30 + 中继分发 15 / 供应链信号 20
 * 理论满分 330，阈值：红 ≥100 / 黄 60-99 / 绿 <60
 *
 * 独立运行（默认，无需任何 MCP 服务器）:
 *   node detect.js https://example.com
 *   node detect.js https://example.com --json
 *   node detect.js https://example.com --created=2026-07-28 --registrar="北京新网" --ns=ns1.363.hk
 *
 * 联动 cti-aggregator-mcp（可选增强）:
 *   node detect.js https://example.com --use-mcp              # 通过 cti-aggregator-mcp 拿数据
 *
 * 作为模块:
 *   const { detectOne, ScoringEngine } = require('./detect.js');
 */

const { investigateDomain: mcpInvestigateDomain } = require('./mcpClient.js');

const age = {
  creationDays: 58,
  registrationDate: '2026-07-08',
  registrar: '北京新网数码信息技术有限公司',
  nameServers: ['ns1.363.hk', 'ns2.363.hk'],   // ← 新增：传入后规则九检查站群共享 NS
};


// ==================== 品牌域名数据库 ====================
const DOMAIN_DATABASE = [
  // 安全软件
  { name: '360安全卫士', officialDomains: ['360.cn', '360.com'], keywords: ['360', '安全卫士', '360safe'] },
  { name: '火绒安全', officialDomains: ['huorong.cn'], keywords: ['火绒', 'huorong'] },
  { name: '腾讯电脑管家', officialDomains: ['guanjia.qq.com'], keywords: ['电脑管家', '腾讯管家'] },
  { name: '金山毒霸', officialDomains: ['duba.net'], keywords: ['金山毒霸', '毒霸', 'duba'] },
  { name: '瑞星杀毒', officialDomains: ['antivirus.rising.com.cn'], keywords: ['瑞星', 'rising'] },
  { name: '微步在线', officialDomains: ['threatbook.cn'], keywords: ['微步', 'threatbook'] },

  // 浏览器
  { name: '360浏览器', officialDomains: ['browser.360.cn'], keywords: ['360浏览器'] },
  { name: 'QQ浏览器', officialDomains: ['browser.qq.com'], keywords: ['QQ浏览器', 'qq浏览器'] },
  { name: '搜狗浏览器', officialDomains: ['ie.sogou.com', 'sogou.com'], keywords: ['搜狗浏览器'] }, // 测绘修正：官方域收敛到 sogou.com；'sogou' 关键词统一放在输入法条目
  { name: 'UC浏览器', officialDomains: ['uc.cn'], keywords: ['UC浏览器', 'uc'] },
  { name: '火狐浏览器', officialDomains: ['mozilla.org', 'firefox.com'], keywords: ['火狐', 'Firefox', 'mozilla'] },
  { name: '谷歌浏览器', officialDomains: ['google.com'], keywords: ['Chrome', '谷歌浏览器'] },
  { name: 'Edge浏览器', officialDomains: ['microsoft.com'], keywords: ['Edge', 'Microsoft Edge'] },

  // 即时通讯
  { name: '微信', officialDomains: ['weixin.qq.com', 'wechat.com'], keywords: ['微信', 'weixin', 'wechat'] },
  { name: 'QQ', officialDomains: ['im.qq.com', 'qq.com'], keywords: ['QQ', '腾讯QQ', 'qq'] },
  { name: '钉钉', officialDomains: ['dingtalk.com'], keywords: ['钉钉', 'dingtalk'] },
  { name: '飞书', officialDomains: ['feishu.cn', 'larkoffice.com'], keywords: ['飞书', 'feishu', 'lark'] },
  { name: '企业微信', officialDomains: ['work.weixin.qq.com'], keywords: ['企业微信', 'wework'] },

  // 输入法
  { name: '搜狗输入法', officialDomains: ['pinyin.sogou.com', 'sogou.com'], keywords: ['搜狗输入法', '搜狗拼音', 'sogou', 'sougo'] }, // 测绘修正：shurufa.sogou.com 曾被误收，收敛进白名单；'sougo' 覆盖拼写变形
  { name: '百度输入法', officialDomains: ['shurufa.baidu.com'], keywords: ['百度输入法', '百度拼音'] },
  { name: '讯飞输入法', officialDomains: ['srf.xunfei.cn'], keywords: ['讯飞输入法', '讯飞', 'xunfei'] },

  // 办公软件
  { name: 'WPS Office', officialDomains: ['wps.cn', 'wps.com'], keywords: ['WPS', '金山办公', 'wps'] },
  { name: '腾讯文档', officialDomains: ['docs.qq.com'], keywords: ['腾讯文档'] },
  { name: '石墨文档', officialDomains: ['shimo.im'], keywords: ['石墨文档', '石墨', 'shimo'] },

  // 视频网站
  { name: '腾讯视频', officialDomains: ['v.qq.com'], keywords: ['腾讯视频', 'qq视频'] },
  { name: '爱奇艺', officialDomains: ['iqiyi.com'], keywords: ['爱奇艺', 'iqiyi'] },
  { name: '优酷', officialDomains: ['youku.com'], keywords: ['优酷', 'youku'] },
  { name: '哔哩哔哩', officialDomains: ['bilibili.com'], keywords: ['哔哩哔哩', 'bilibili', 'B站'] },
  { name: '芒果TV', officialDomains: ['mgtv.com'], keywords: ['芒果TV', 'mgtv'] },
  { name: '西瓜视频', officialDomains: ['ixigua.com'], keywords: ['西瓜视频', 'ixigua'] },

  // 音乐软件
  { name: '网易云音乐', officialDomains: ['music.163.com'], keywords: ['网易云音乐', '网易云', 'cloudmusic'] },
  { name: 'QQ音乐', officialDomains: ['y.qq.com'], keywords: ['QQ音乐', 'qq音乐'] },
  { name: '酷狗音乐', officialDomains: ['kugou.com'], keywords: ['酷狗', 'kugou'] },
  { name: '酷我音乐', officialDomains: ['kuwo.cn'], keywords: ['酷我', 'kuwo'] },

  // 云存储/网盘
  { name: '百度网盘', officialDomains: ['pan.baidu.com'], keywords: ['百度网盘', '百度云盘'] },
  { name: '阿里云盘', officialDomains: ['aliyundrive.com', 'alipan.com'], keywords: ['阿里云盘', 'aliyundrive'] },
  { name: '夸克网盘', officialDomains: ['pan.quark.cn'], keywords: ['夸克网盘', '夸克'] },
  { name: '迅雷云盘', officialDomains: ['pan.xunlei.com'], keywords: ['迅雷云盘'] },

  // AI Chat
  { name: '文心一言', officialDomains: ['yiyan.baidu.com'], keywords: ['文心一言', 'yiyan', '文心'] },
  { name: '通义千问', officialDomains: ['tongyi.aliyun.com'], keywords: ['通义千问', 'tongyi', 'qianwen'] },
  { name: '豆包', officialDomains: ['doubao.com'], keywords: ['豆包', 'doubao'] },
  { name: '讯飞星火', officialDomains: ['xinghuo.xfyun.cn'], keywords: ['讯飞星火', 'xinghuo', 'xfyun'] },
  { name: 'Kimi', officialDomains: ['kimi.moonshot.cn'], keywords: ['Kimi', 'kimi', 'moonshot'] },
  { name: 'DeepSeek', officialDomains: ['deepseek.com', 'chat.deepseek.com'], keywords: ['DeepSeek', 'deepseek'] },
  { name: '智谱清言', officialDomains: ['chatglm.cn'], keywords: ['智谱清言', 'chatglm', '智谱'] },
  { name: 'ChatGPT', officialDomains: ['openai.com', 'chatgpt.com'], keywords: ['ChatGPT', 'chatgpt', 'OpenAI'] },

  // 下载工具
  { name: '迅雷', officialDomains: ['xunlei.com'], keywords: ['迅雷', 'xunlei'] },
  { name: 'IDM', officialDomains: ['internetdownloadmanager.com'], keywords: ['IDM', 'Internet Download Manager'] },

  // 压缩工具
  { name: 'WinRAR', officialDomains: ['rarlab.com'], keywords: ['WinRAR', 'winrar', 'rar'] },
  { name: '7-Zip', officialDomains: ['7-zip.org'], keywords: ['7-Zip', '7zip', '7z'] },

  // 电商
  { name: '淘宝', officialDomains: ['taobao.com', 'tmall.com'], keywords: ['淘宝', 'taobao', '天猫'] },
  { name: '京东', officialDomains: ['jd.com'], keywords: ['京东', 'jd'] },
  { name: '拼多多', officialDomains: ['pinduoduo.com'], keywords: ['拼多多', 'pinduoduo'] },
  { name: '美团', officialDomains: ['meituan.com'], keywords: ['美团', 'meituan'] },
  { name: '闲鱼', officialDomains: ['goofish.com'], keywords: ['闲鱼', 'goofish'] },

  // 地图/出行
  { name: '高德地图', officialDomains: ['amap.com', 'gaode.com'], keywords: ['高德地图', '高德', 'amap'] },
  { name: '滴滴出行', officialDomains: ['didiglobal.com'], keywords: ['滴滴', 'didi'] },

  // 支付
  { name: '支付宝', officialDomains: ['alipay.com'], keywords: ['支付宝', 'alipay', 'zhifubao'] },
  { name: '微信支付', officialDomains: ['pay.weixin.qq.com'], keywords: ['微信支付', 'wechatpay'] },

  // 开发者工具
  { name: '阿里云', officialDomains: ['aliyun.com'], keywords: ['阿里云', 'aliyun'] },
  { name: '腾讯云', officialDomains: ['cloud.tencent.com'], keywords: ['腾讯云'] },
  { name: '华为云', officialDomains: ['huaweicloud.com'], keywords: ['华为云', 'huaweicloud'] },
  { name: 'CSDN', officialDomains: ['csdn.net'], keywords: ['CSDN', 'csdn'] },
  { name: 'GitHub', officialDomains: ['github.com'], keywords: ['Github', 'GitHub'] },
  { name: 'Gitee', officialDomains: ['gitee.com'], keywords: ['Gitee', 'gitee', '码云'] },
  { name: '掘金', officialDomains: ['juejin.cn'], keywords: ['掘金', 'juejin'] },
  { name: 'V2EX', officialDomains: ['v2ex.com'], keywords: ['V2EX', 'v2ex'] },

  // 系统工具
  { name: 'ToDesk', officialDomains: ['todesk.com'], keywords: ['ToDesk', 'todesk'] },
  { name: '向日葵', officialDomains: ['sunlogin.oray.com', 'oray.com', 'sunlogin.com'], keywords: ['向日葵', 'sunlogin', 'oray'] }, // 测绘修正：补 oray.com/sunlogin.com，避免 store.oray.com、d.sunlogin.com 官方子域被误判（20个误收官方域实锤）
  { name: 'TeamViewer', officialDomains: ['teamviewer.com'], keywords: ['TeamViewer', 'teamviewer'] },
  { name: 'AnyDesk', officialDomains: ['anydesk.com'], keywords: ['AnyDesk', 'anydesk'] },
  { name: '驱动精灵', officialDomains: ['drivergenius.com'], keywords: ['驱动精灵', 'drivergenius'] },
  { name: '鲁大师', officialDomains: ['ludashi.com'], keywords: ['鲁大师', 'ludashi'] },
  { name: '爱思助手', officialDomains: ['i4.cn'], keywords: ['爱思助手', 'i4tools', 'i4cn', 'aisizhushou', 'aisi'] }, // 2026-09 刘叔情报：银狐伪装爱思助手官网（i4 系 iOS 刷机/管理工具，官方自查 2024-2025 曝光 121 起伪破解版病毒案例）；官方唯一域 i4.cn（www/pc/all/m 子域经后缀匹配自动豁免）；'i4tools'=官方安装包名（覆盖规则B/D），'i4cn'=抓 i4cn.com/i4-cn.com（去连字符命中），'aisizhushou'/'aisi'=拼音变体；刻意不加 'i4'：2字符段匹配无长度门槛，BMW i4/i4.io 等无关域会误报

  // 游戏平台/加速器
  { name: 'WeGame', officialDomains: ['wegame.com.cn'], keywords: ['WeGame', 'wegame'] },
  { name: 'Minecraft', officialDomains: ['minecraft.net'], keywords: ['Minecraft', '我的世界'] },
  { name: '网易UU加速器', officialDomains: ['uu.163.com', 'uuyc.163.com'], keywords: ['UU加速器', '网易UU', 'uu163'] }, // uuyc.163.com 曾被误收；'uu163' 覆盖 uu163.xyz 类仿冒
  { name: '迅游加速器', officialDomains: ['xunyou.com'], keywords: ['迅游', 'xunyou'] },
  { name: '雷神加速器', officialDomains: ['leigod.com'], keywords: ['雷神', 'leigod'] },

  // 新闻/信息
  { name: '今日头条', officialDomains: ['toutiao.com'], keywords: ['今日头条', '头条', 'toutiao'] },
  { name: '百度', officialDomains: ['baidu.com'], keywords: ['百度', 'baidu'] },
  { name: '知乎', officialDomains: ['zhihu.com'], keywords: ['知乎', 'zhihu'] },
  { name: '虎扑', officialDomains: ['hupu.com'], keywords: ['虎扑', 'hupu'] },

  // ==================== 2026-08 测绘反哺（L1 口径 N=17,342 Top 品牌，含子品牌拆分） ====================
  // 口径：按「仿冒对象」颗粒度建条目，子品牌独立，不按品牌系归组

  // VPN / 代理工具（测绘重灾区：Clash 系合计 1,909、快连 503、Shadowrocket 303）
  { name: 'Clash Verge', officialDomains: ['clash-verge-rev.github.io'], keywords: ['clash', 'clashverge', 'clashmeta', 'clash-verge'] },
  { name: '快连VPN', officialDomains: ['letsvpn.com'], keywords: ['快连', 'letsvpn', 'kuailian'] },
  { name: 'Shadowrocket', officialDomains: ['shadowrocketapps.com'], keywords: ['shadowrocket', '小火箭'] },
  { name: 'Proton VPN', officialDomains: ['protonvpn.com', 'proton.me'], keywords: ['protonvpn', 'proton'] },
  { name: 'ExpressVPN', officialDomains: ['expressvpn.com'], keywords: ['expressvpn'] },

  // 即时通讯补充（LINE 1,075、WhatsApp 201）
  { name: 'LINE', officialDomains: ['line.me', 'line.biz'], keywords: ['line'] }, // 4字符短词仅规则A精确段匹配可命中，误报可控
  { name: 'WhatsApp', officialDomains: ['whatsapp.com'], keywords: ['whatsapp'] },
  { name: 'Telegram', officialDomains: ['telegram.org', 't.me'], keywords: ['telegram', '纸飞机', '电报'] },
  { name: 'Signal', officialDomains: ['signal.org', 'signal.me'], keywords: ['signal'] },
  { name: 'Zoom', officialDomains: ['zoom.us', 'zoom.com'], keywords: ['zoom'] },
  { name: 'Discord', officialDomains: ['discord.com', 'discord.gg'], keywords: ['discord'] },

  // QQ/腾讯子品牌拆分（测绘仿冒对象：TIM 101、腾讯游戏 77、QQ音乐 73、QQ管家 27、QQ浏览器 22、QQ邮箱 6、QQ会议 4）
  { name: 'TIM', officialDomains: ['tim.qq.com'], keywords: ['TIM'] }, // 'tim' 仅精确段匹配可命中（timing 不误报），接受少量误报换取召回
  { name: '腾讯会议', officialDomains: ['meeting.tencent.com', 'voovmeeting.com'], keywords: ['腾讯会议', 'voovmeeting'] },
  { name: 'QQ邮箱', officialDomains: ['mail.qq.com'], keywords: ['QQ邮箱'] },
  { name: '腾讯游戏', officialDomains: ['game.qq.com'], keywords: ['腾讯游戏'] },

  // 网易系子品牌拆分（测绘：UU 164、云音乐 151、有道 56、网易邮箱/游戏/新闻长尾）
  { name: '网易', officialDomains: ['163.com', '126.com', 'netease.com'], keywords: ['netease', '网易', '163', '126', 'wangyi'] }, // 数字关键词仅规则A精确段/规则C堆叠可命中，正常域名极少用纯数字段，误报可控
  { name: '有道', officialDomains: ['youdao.com'], keywords: ['youdao', '有道'] },

  // 驱动/系统工具补充（测绘长尾：驱动人生、万能驱动）
  { name: '驱动人生', officialDomains: ['160.com'], keywords: ['驱动人生'] },
  { name: '万能驱动', officialDomains: [], keywords: ['万能驱动'] },

  // 网盘/多媒体补充（123云盘、汽水音乐、茶杯狐影视）
  { name: '123云盘', officialDomains: ['123pan.com'], keywords: ['123pan', '123云盘'] },
  { name: '汽水音乐', officialDomains: [], keywords: ['汽水音乐'] },
  { name: '茶杯狐', officialDomains: [], keywords: ['茶杯狐', 'cupfox'] },

  // 营销/客服外挂（银狐投放长尾：易歪歪、旺商聊）
  { name: '易歪歪', officialDomains: [], keywords: ['易歪歪'] },
  { name: '旺商聊', officialDomains: [], keywords: ['旺商聊'] },

  // AI Chat 补充（DeepSeek 184 已有，补 Copilot/Gemini/Claude/Gmail）
  { name: 'Microsoft Copilot', officialDomains: ['copilot.microsoft.com'], keywords: ['copilot'] },
  { name: 'Gemini', officialDomains: ['gemini.google.com'], keywords: ['gemini'] },
  { name: 'Claude', officialDomains: ['claude.ai', 'anthropic.com'], keywords: ['claude'] },
  { name: 'Gmail', officialDomains: ['gmail.com', 'mail.google.com'], keywords: ['gmail'] }, // 覆盖 gmaiillli.com 类混淆域（规则D编辑距离）

  // 游戏/平台补充（Steam、原神/米哈游）
  { name: 'Steam', officialDomains: ['steampowered.com', 'steamcommunity.com'], keywords: ['steam', 'steampowered'] },
  { name: '原神', officialDomains: ['yuanshen.com', 'genshin.hoyoverse.com'], keywords: ['genshin', 'yuanshen', '原神'] },
  { name: '米哈游', officialDomains: ['mihoyo.com', 'hoyoverse.com'], keywords: ['mihoyo', 'hoyoverse', '米哈游'] },

  // 安全/浏览器补充（卡巴斯基、诺顿、Brave、Opera、比特浏览器）
  { name: '卡巴斯基', officialDomains: ['kaspersky.com'], keywords: ['kaspersky', '卡巴斯基'] },
  { name: '诺顿', officialDomains: ['norton.com'], keywords: ['norton', '诺顿'] },
  { name: 'Brave', officialDomains: ['brave.com'], keywords: ['brave'] },
  { name: 'Opera', officialDomains: ['opera.com'], keywords: ['opera'] },
  { name: '比特浏览器', officialDomains: ['bitbrowser.cn'], keywords: ['bitbrowser', '比特浏览器'] },

  // 多媒体/社交/交易补充（美图、抖音、快手、OKX、币安）
  { name: '美图秀秀', officialDomains: ['meitu.com'], keywords: ['meitu', '美图秀秀'] },
  { name: '抖音', officialDomains: ['douyin.com'], keywords: ['douyin', '抖音'] },
  { name: '快手', officialDomains: ['kuaishou.com'], keywords: ['kuaishou', '快手'] },
  { name: 'OKX', officialDomains: ['okx.com'], keywords: ['okx', '欧易'] },
  { name: '币安', officialDomains: ['binance.com'], keywords: ['binance', '币安'] },

  // 2026-09-04 实测补充：银狐「工具软件」仿冒站群（8 个品牌全部实测未命中，逐一补入）
  // 共性：{修饰词}-{品牌} 或 {品牌}-{产品} + .com.cn，2026-05~07 集中注册，共享 363.hk / julydns.com NS
  // 官方域均已于 2026-09-04 逐一核实，避免重蹈 DeepSeek 漏主域覆辙
  { name: 'Calibre', officialDomains: ['calibre-ebook.com'], keywords: ['calibre'] },
  { name: 'draw.io', officialDomains: ['diagrams.net', 'draw.io'], keywords: ['drawio', 'diagrams'] },
  // MindMaster 现名「万兴脑图 / EdrawMind」；仿冒域 mindmoster 为 a→o 单字符替换，靠规则D编辑距离捕获
  { name: 'MindMaster', officialDomains: ['edrawsoft.com', 'edrawsoft.cn'], keywords: ['mindmaster', 'edrawmind', '万兴脑图'] },
  { name: 'oCam', officialDomains: ['ohsoft.net'], keywords: ['ocam'] },
  // 注意：ocam-soft.com.cn 自称官方但非 OhSoft 所有（韩国厂商），未列入白名单，避免误豁免
  { name: '雷蛇 Razer', officialDomains: ['razer.com', 'razerzone.com'], keywords: ['razer', '雷蛇'] },
  { name: '赛睿 SteelSeries', officialDomains: ['steelseries.com'], keywords: ['steelseries', '赛睿'] },
  { name: 'Sejda', officialDomains: ['sejda.com'], keywords: ['sejda'] },
  { name: 'DiskGenius', officialDomains: ['diskgenius.com', 'diskgenius.cn'], keywords: ['diskgenius', 'diskgen'] },
];

// ==================== 常量 ====================
const PROMO_KEYWORDS = [
  '下载', '产品', '软件', '安装', '免费', '官方', '应用', '工具',
  '版本', '最新', '破解', '注册', '激活', '绿色', '汉化', '插件',
  '专业版', '正式版', '购买', '激活码', '注册机', '补丁', '试用',
  '客户端', '安装包', '精简版', '去广告', '便携版',
  'download', 'product', 'software', 'install', 'free', 'official',
  'app', 'tool', 'version', 'latest', 'crack', 'register', 'activate',
  'pro', 'premium', 'setup', 'license', 'keygen', 'patch', 'trial',
  'portable', 'release', 'full version'
];

const ARCHIVE_EXTENSIONS = ['.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.iso', '.cab'];
const DOWNLOAD_KEYWORDS = ['下载', 'download', '下載', '立即下载', '免费下载', '高速下载', '安全下载', '点击下载', '直接下载', '本地下载', '官方下载', 'Download Now', 'Free Download'];
const PROVINCE_ABBREVIATIONS = ['京', '津', '沪', '渝', '冀', '豫', '云', '滇', '辽', '黑', '湘', '皖', '鲁', '新', '苏', '浙', '赣', '鄂', '桂', '甘', '陇', '晋', '蒙', '陕', '秦', '吉', '闽', '贵', '黔', '粤', '川', '蜀', '青', '藏', '琼', '宁'];

const ICP_EXEMPT_DOMAINS = new Set([
  'google.com', 'youtube.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'meta.com', 'facebook.com', 'twitter.com', 'x.com', 'github.com', 'discord.com',
  'telegram.org', 'linkedin.com', 'reddit.com', 'instagram.com', 'whatsapp.com',
  'wikipedia.org', 'mozilla.org', 'stackoverflow.com', 'npmjs.com', 'pypi.org',
  'docker.com', 'kubernetes.io', 'vercel.com', 'netlify.com', 'heroku.com',
  'cloudflare.com', 'firebase.google.com', 'jetbrains.com', 'spotify.com',
  'netflix.com', 'twitch.tv', 'vimeo.com', 'steamcommunity.com', 'epicgames.com',
  'minecraft.net', 'dropbox.com', 'slack.com', 'zoom.us', 'figma.com',
  'canva.com', 'openai.com', 'chatgpt.com', 'anthropic.com', 'huggingface.co',
  'arxiv.org', 'ubuntu.com', 'debian.org', 'archlinux.org', 'gitlab.com',
  'bitbucket.org', 'medium.com', 'wordpress.com', 'blogger.com', 'notion.so',
  'readthedocs.io', 'gitbook.io', 'codepen.io', 'jsfiddle.net', 'codesandbox.io',
  'replit.com', 'outlook.com', 'icloud.com', 'discord.gg', 't.me',
  // 2026-08 测绘反哺：新增品牌对应的海外官方域（有中文页面的外国站点，避免规则三误伤）
  'line.me', 'letsvpn.com', 'proton.me', 'protonvpn.com', 'signal.org', 'zoom.com',
  'brave.com', 'opera.com', 'kaspersky.com', 'norton.com', 'binance.com', 'okx.com',
]);

// ==================== 供应链/下载信号常量（2026-08 测绘标定，L3 辅助） ====================
const DOWNLOAD_DOMAIN_BLACKLIST = new Set([
  // 待测绘下载域沉淀填充；当前留空，规则八降级为纯跨域判定
]);

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.icu', '.lol', '.sbs', '.click'];

// 站群外壳域模式（2026-09 实测：apps-aisi.com.cn / apps-hupu.com.cn 同一伙人批量注册）
// 2026-09-04 扩充前缀：app-/cn-/pc-/zh-/gw- 等（实测 app-microsoft-edge / cn-drawio / pc-razerzone / zh-diskgenius / gw-sogou）
const SHELL_DOMAIN_RE = /^(?:app|apps|cn|pc|zh|gw|web|www|dl|download|soft|official|client)-[a-z0-9]+(?:-[a-z0-9]+)*\.com\.cn$/i;

// 连字符仿冒域（2026-09-04 实测：16 个银狐域中 9 个为连字符 .com.cn——
// baidu-pan / calibre-ebook / cn-drawio / gw-sogou / ocam-pc / pc-razerzone / steelseries-cn / zh-diskgenius / app-microsoft-edge）
// 正规中文品牌官网极少使用「修饰词-品牌」式连字符 .com.cn，命中即可疑
const HYPHEN_SPOOF_RE = /^[a-z0-9]+-[a-z0-9-]+\.com\.cn$/i;

// 短主域「子域农场」（2026-09-04 实测：两字母 .cn 主域 hl.cn 下挂 kaspersky-lab / sejda / translate-youdao 三个品牌子域）
// 手法本质：注册一个主域即可无限开设品牌子域，比逐品牌注册成本更低、更难被 IOC 封堵覆盖
const SHORT_BASE_SUB_RE = /^[a-z0-9][a-z0-9-]*\.[a-z]{2}\.cn$/i;

// 站群共享 NS（2026-09-04 实测：ns1/ns2.363.hk 承载 8 个仿冒域、ns1/ns2.julydns.com 承载 3 个）
// NS 复用 = 同一操作者基础设施，比注册商信号更硬——注册商可随时换，自建 NS 迁移成本高
const SUSPICIOUS_NAME_SERVERS = ['363.hk', 'julydns.com'];

const SUSPICIOUS_REGISTRARS = [
  '新网', 'xin net', 'web commerce communications', 'dominet', 'gname',
];

const SUSPICIOUS_REGISTRANT_EMAIL_DOMAINS = new Set([
  'xxcloud.ai', 'baituo.io', 'ningqi.live', 'cloudworld.club', 'fengyun.lol', 'gmaiillli.com',
  // 2026-09-01 实测：apps-aisi.com.cn 注册邮箱 ind-350@vervetech.cc（编号式批量邮箱，邮箱域本身 Gname 注册 + 香港主机）
  'vervetech.cc',
]);

// 中继分发模式（2026-09 实测：apps-hupu.com.cn 页面内嵌 noah-ssh 中继池——relays.json 分发节点 + /api.php 动态下链）
// 下载链接不写死在页面，通过中继节点池动态拉取，静态抓取看不到最终地址
const RELAY_PATTERNS = [
  /relays\.json/i,                 // 中继节点列表配置
  /\.workers\.dev/i,               // Cloudflare Workers 免费中继节点
  /download_link/i,                // JS 动态下链字段
  /\/api\.php\?t=/i,               // 时间戳防缓存动态下链接口
];

// ==================== 工具函数 ====================
function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const m = [];
  for (let i = 0; i <= b.length; i++) m[i] = [i];
  for (let j = 0; j <= a.length; j++) m[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      m[i][j] = Math.min(m[i-1][j] + 1, m[i][j-1] + 1, m[i-1][j-1] + (a[j-1] === b[i-1] ? 0 : 1));
    }
  }
  return m[b.length][a.length];
}

function splitIntoSegments(label) {
  return label.split(/[-_]/);
}

// ==================== 域名数据库类 ====================
class DomainDatabase {
  static detectSpoof(hostname) {
    const normalized = hostname.replace(/^www\./i, '').toLowerCase();
    const keywordToEntries = new Map();
    for (const entry of DOMAIN_DATABASE) {
      for (const kw of entry.keywords) {
        const key = kw.toLowerCase();
        if (!keywordToEntries.has(key)) keywordToEntries.set(key, []);
        keywordToEntries.get(key).push(entry);
      }
    }
    const sortedKeywords = [...keywordToEntries.keys()].sort((a, b) => b.length - a.length);

    const _checkRules = (labels, allSegs, labelSegs) => {
      for (const kw of sortedKeywords) {
        // 规则A：精确段匹配
        for (const segs of labelSegs) {
          for (const seg of segs) {
            if (seg === kw) {
              const entry = keywordToEntries.get(kw)[0];
              return { entry, matchType: 'segment_exact_match', matchedBy: `段 "${seg}" 精确匹配关键词 "${kw}"` };
            }
          }
        }
        // 规则B：标签子串包含（kw>=5）
        if (kw.length >= 5) {
          for (const label of labels) {
            if (label.includes(kw)) {
              const entry = keywordToEntries.get(kw)[0];
              return { entry, matchType: 'substring_include', matchedBy: `标签 "${label}" 包含关键词 "${kw}"` };
            }
          }
        }
        // 规则C：关键词堆叠
        let hitCount = 0;
        for (const seg of allSegs) { if (seg === kw) hitCount++; }
        if (hitCount >= 3) {
          const entry = keywordToEntries.get(kw)[0];
          return { entry, matchType: 'keyword_stuffing', matchedBy: `关键词 "${kw}" 重复出现 ${hitCount} 次` };
        }
      }
      return null;
    };

    const labels = normalized.split('.');
    const allSegments = [], labelSegments = [];
    for (const label of labels) {
      const segs = splitIntoSegments(label);
      labelSegments.push(segs);
      for (const s of segs) allSegments.push(s);
    }

    let result = _checkRules(labels, allSegments, labelSegments);
    if (result) return result;

    // 去连字符二次检测
    if (normalized.includes('-') || normalized.includes('_')) {
      const deHyphened = normalized.replace(/[-_]/g, '');
      const dhLabels = deHyphened.split('.');
      const dhAllSegs = [], dhLabelSegs = [];
      for (const label of dhLabels) {
        const segs = splitIntoSegments(label);
        dhLabelSegs.push(segs);
        for (const s of segs) dhAllSegs.push(s);
      }
      result = _checkRules(dhLabels, dhAllSegs, dhLabelSegs);
      if (result) return result;
    }

    // 去重复字母二次检测（覆盖 gmaiillli.com 类字母堆叠混淆，2026-08 测绘反哺）
    const collapsed = normalized.replace(/(.)\1+/g, '$1');
    if (collapsed !== normalized) {
      const cLabels = collapsed.split('.');
      const cAllSegs = [], cLabelSegs = [];
      for (const label of cLabels) {
        const segs = splitIntoSegments(label);
        cLabelSegs.push(segs);
        for (const s of segs) cAllSegs.push(s);
      }
      result = _checkRules(cLabels, cAllSegs, cLabelSegs);
      if (result) return { entry: result.entry, matchType: result.matchType, matchedBy: result.matchedBy + '（去重复字母后命中，字母堆叠混淆）' };
    }

    // 规则D：约束编辑距离（kw>=6）
    for (const kw of sortedKeywords) {
      if (kw.length < 6) continue;
      for (const label of labels) {
        if (Math.abs(label.length - kw.length) > 2) continue;
        const dist = levenshtein(label, kw);
        if (dist >= 1 && dist <= 2) {
          const entry = keywordToEntries.get(kw)[0];
          return { entry, matchType: 'typosquat', matchedBy: `编辑距离 ${dist}: "${label}" ≈ "${kw}"` };
        }
      }
    }
    return null;
  }

  static findByDomain(hostname) {
    const normalized = hostname.replace(/^www\./i, '').toLowerCase();
    for (const entry of DOMAIN_DATABASE) {
      for (const domain of entry.officialDomains) {
        const d = domain.replace(/^www\./i, '').toLowerCase();
        if (normalized === d || normalized.endsWith('.' + d)) return entry;
      }
    }
    return null;
  }
}

// ==================== ICP备案检测类 ====================
class IcpUtils {
  static ICP_REGEX = new RegExp(`(${PROVINCE_ABBREVIATIONS.join('|')})\\s*ICP\\s*[备证]\\s*\\d{6,12}\\s*号`, 'gi');
  static POLICE_REGEX = new RegExp(`(${PROVINCE_ABBREVIATIONS.join('|')})\\s*公网安备\\s*\\d{10,}\\s*号`, 'g');

  static searchIcpNumber(text) {
    if (!text) return { found: false, numbers: [] };
    const matches = text.match(this.ICP_REGEX) || [];
    const policeMatches = text.match(this.POLICE_REGEX) || [];
    const allMatches = [...new Set([...matches, ...policeMatches])];
    return { found: allMatches.length > 0, numbers: allMatches };
  }

  static isIcpExempt(domain) {
    if (!domain) return false;
    const normalized = domain.replace(/^www\./i, '').toLowerCase();
    if (ICP_EXEMPT_DOMAINS.has(normalized)) return true;
    const parts = normalized.split('.');
    for (let i = 1; i < parts.length; i++) {
      if (ICP_EXEMPT_DOMAINS.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  }

  static detectCJKContent(text) {
    if (!text) return { hasCJK: false, cjkCount: 0 };
    let cjkCount = 0;
    for (let i = 0; i < text.length; i++) {
      const code = text.codePointAt(i);
      if ((code >= 0x4E00 && code <= 0x9FFF) || (code >= 0x3400 && code <= 0x4DBF) || (code >= 0xF900 && code <= 0xFAFF)) cjkCount++;
    }
    return { hasCJK: cjkCount >= 30, cjkCount };
  }
}

// ==================== 评分引擎类 ====================
class ScoringEngine {
  static evaluate(url, pageContent = '', domainAge = null) {
    let hostname;
    try { hostname = new URL(url).hostname; } catch (e) { return { error: '无效的URL格式' }; }

    const results = {};
    let totalScore = 0;

    results.rule1 = this._evaluateRule1(hostname);
    totalScore += results.rule1.score;

    results.rule3 = this._evaluateRule3(hostname, pageContent);
    totalScore += results.rule3.score;

    // P1 修复（2026-09）：neutral（外国站点豁免）也纳入早期退出，避免豁免域误入规则四/五
    const isOfficial = !results.rule1.triggered &&
                       (results.rule3.status === 'pass' || results.rule3.status === 'neutral');

    if (!isOfficial) {
      results.rule4 = this._evaluateRule4(pageContent, url);
      totalScore += results.rule4.score;
      results.rule5 = this._evaluateRule5(pageContent);
      totalScore += results.rule5.score;

      // 规则八：跨域下载检测
      results.rule8 = this._evaluateRule8(pageContent, hostname);
      totalScore += results.rule8.score;

      // 规则六：域名年龄（RDAP 数据由 analyzeWebsite 异步查询后传入）
      results.rule6 = this._evaluateRule6(domainAge);
      totalScore += results.rule6.score;

      // 规则九：供应链辅助信号（L3，不可单独定罪）
      results.rule9 = this._evaluateRule9(hostname, domainAge);
      totalScore += results.rule9.score;

      // 规则七：老域名补偿（负分，防负保护见实现）
      results.rule7 = this._evaluateRule7(domainAge, totalScore, results.rule6.score);
      totalScore += results.rule7.score;
    } else {
      results.rule4 = { score: 0, triggered: false, status: 'pass', detail: '官方网站，跳过链接分析' };
      results.rule5 = { score: 0, triggered: false, status: 'pass', detail: '官方网站，跳过代码工程化检查' };
      results.rule6 = { score: 0, triggered: false, status: 'neutral', detail: '官方网站，跳过域名年龄评分' };
      results.rule7 = { score: 0, triggered: false, status: 'neutral', detail: '官方网站，跳过老域名补偿' };
      results.rule8 = { score: 0, triggered: false, status: 'pass', detail: '官方网站，跳过跨域下载检测' };
      results.rule9 = { score: 0, triggered: false, status: 'pass', detail: '官方网站，跳过供应链信号检测' };
    }

    totalScore = Math.max(0, totalScore);
    results.totalScore = totalScore;

    // 三层判定：L1 硬证据短路 → 总分阈值
    if (results.rule1.triggered) {
      const pageDownloadSignal = results.rule4.score > 0 || results.rule5.score > 0 || results.rule8.score > 0;
      const newDomainSignal = results.rule6 && results.rule6.score >= 45;
      results.riskLevel = (pageDownloadSignal || newDomainSignal || totalScore >= 100) ? 'danger' : 'warning';
      if (pageDownloadSignal || newDomainSignal) {
        results.shortCircuit = 'L1硬证据短路：域名仿冒 + ' + (pageDownloadSignal ? '页面下载信号' : '新注册域名');
      }
    } else {
      results.riskLevel = totalScore >= 100 ? 'danger' : (totalScore >= 60 ? 'warning' : 'safe');
    }

    // 中文化展示字段（2026-09：内部英文 status/riskLevel 保留供逻辑判断，输出层附加中文说明）
    const STATUS_ZH = { pass: '通过', warn: '警告', neutral: '未判定', triggered: '触发' };
    const RISK_ZH = { danger: { label: '危险', color: '红色' }, warning: { label: '警告', color: '黄色' }, safe: { label: '安全', color: '绿色' } };
    for (const key of Object.keys(results)) {
      const v = results[key];
      if (v && typeof v === 'object' && 'status' in v) {
        v.statusZh = STATUS_ZH[v.status] || v.status;
      }
    }
    const rz = RISK_ZH[results.riskLevel] || { label: results.riskLevel, color: '' };
    results.riskLevelZh = rz.label;
    results.riskLevelColor = rz.color;
    return results;
  }

  static _evaluateRule1(domain) {
    const result = { score: 0, triggered: false, status: 'pass', detail: '', matchedEntry: null };
    if (domain.endsWith('.edu.cn')) { result.detail = '教育机构域名，跳过检测'; return result; }
    const official = DomainDatabase.findByDomain(domain);
    if (official) { result.detail = '官方网站，域名匹配'; return result; }
    const spoof = DomainDatabase.detectSpoof(domain);
    if (spoof) {
      result.score = 60;
      result.triggered = true;
      // 2026-09-04 修复：命中硬证据时 status 必须同步为 triggered，
      // 否则报告中「60 分仿冒」却显示状态「通过」，与 15 分弱信号的 warn 语义反转
      result.status = 'triggered';
      result.matchedEntry = spoof.entry;
      result.detail = `域名仿冒检测命中：${spoof.matchedBy}`;
    }
    return result;
  }

  static _evaluateRule3(domain, pageText) {
    const result = { score: 0, triggered: false, status: 'pass', detail: '', icpFound: false };
    const official = DomainDatabase.findByDomain(domain);
    if (official) { result.detail = '官方网站，ICP检查通过'; return result; }
    if (IcpUtils.isIcpExempt(domain)) { result.status = 'neutral'; result.detail = '外国站点，ICP检查不适用'; return result; }
    const icpResult = IcpUtils.searchIcpNumber(pageText);
    const cjkResult = IcpUtils.detectCJKContent(pageText);
    if (icpResult.found) {
      result.icpFound = true;
      result.detail = `检测到ICP备案号: ${icpResult.numbers[0]}`;
    } else if (cjkResult.hasCJK) {
      // 2026-08 降权：测绘显示银狐 .cn 仿冒域普遍已完成真实备案，「无ICP」判别力有限
      result.score = 30;
      result.triggered = true;
      // 2026-09-04 修复：与规则一同款 bug，命中强信号需同步 status，避免语义反转
      result.status = 'triggered';
      result.detail = `未检测到ICP备案号（页面含${cjkResult.cjkCount}个中文字符）`;
    } else {
      result.score = 15;
      result.status = 'warn';
      result.detail = '无中文内容，缺少ICP为弱信号';
    }
    return result;
  }

  static _evaluateRule4(pageText, url) {
    const result = { score: 0, triggered: false, status: 'pass', detail: '' };
    if (!pageText) { result.status = 'neutral'; result.detail = '未收集到页面内容'; return result; }
    let score = 0;
    const reasons = [];
    const lowerText = pageText.toLowerCase();
    const externalArchiveLinks = (pageText.match(/https?:\/\/[^\s<>"]+?(?:\.zip|\.rar|\.7z|\.tar|\.gz|\.tgz|\.bz2|\.xz|\.iso|\.cab)/gi) || []).length;
    if (externalArchiveLinks >= 1) { score += 10; reasons.push(`${externalArchiveLinks}个外链指向压缩包`); }
    const hasDownloadBtn = DOWNLOAD_KEYWORDS.some(kw => lowerText.includes(kw.toLowerCase()));
    if (hasDownloadBtn) { score += 10; reasons.push('页面包含下载关键词'); }
    const hasSuspiciousLinks = (pageText.match(/https?:\/\/[^\s<>"]+?(?:down|download|dl|setup|install)\b/gi) || []).length;
    if (hasSuspiciousLinks >= 2) { score += 20; reasons.push(`${hasSuspiciousLinks}个可疑下载链接`); }
    result.score = score;
    result.triggered = score > 0;
    result.detail = score > 0 ? `链接分析: ${reasons.join(', ')} (+${score})` : '链接分析正常';
    return result;
  }

  static _evaluateRule5(pageText) {
    const result = { score: 0, triggered: false, status: 'pass', detail: '' };
    if (!pageText || pageText.length < 500) { result.detail = '页面文本不足，跳过检测'; return result; }
    const signals = [];
    const lowerText = pageText.toLowerCase();
    const hasFramework = /(react|vue|angular|webpack|jquery|bootstrap)/i.test(pageText);
    if (!hasFramework) signals.push('未检测到主流框架');
    const externalResourceCount = (pageText.match(/https?:\/\/[^\s<>"]+\.(?:js|css|png|jpg|jpeg|gif|svg|woff|woff2)/gi) || []).length;
    if (externalResourceCount < 5) signals.push(`外部资源仅${externalResourceCount}个`);
    const domComplexity = (pageText.match(/<[^>]+>/g) || []).length;
    if (domComplexity < 100) signals.push(`DOM节点仅${domComplexity}个`);
    if (signals.length >= 3) { result.score = 30; result.detail = `代码工程化高度可疑: ${signals.join(', ')} (+30)`; }
    else if (signals.length >= 2) { result.score = 20; result.detail = `代码工程化中度可疑: ${signals.join(', ')} (+20)`; }
    // Emoji密度检测
    const keywordMatchCount = PROMO_KEYWORDS.filter(kw => lowerText.includes(kw.toLowerCase())).length;
    if (keywordMatchCount >= 1) {
      const emojiRegex = /\p{Emoji_Presentation}|\p{Emoji}️/gu;
      const emojiMatches = pageText.match(emojiRegex) || [];
      const emojiCount = emojiMatches.length;
      if (emojiCount > 0) {
        const density = (emojiCount / pageText.length) * 1000;
        if (density >= 2.0) {
          const emojiScore = density >= 10.0 ? 30 : Math.floor((density - 2) / 8 * 30);
          result.score += emojiScore;
          result.detail += (result.detail ? ' | ' : '') + `Emoji密度高(${emojiCount}个Emoji，密度${density.toFixed(1)}，+${emojiScore})`;
        }
      }
    }
    result.triggered = result.score > 0;
    if (!result.detail) result.detail = '代码工程化检测通过';
    return result;
  }

  // 规则六：域名年龄评分（a=2, b=6，2026-08 测绘标定）
  static _evaluateRule6(domainAge) {
    const result = { score: 0, triggered: false, status: 'neutral', detail: '' };
    if (!domainAge) { result.detail = 'RDAP查询失败，跳过域名年龄评分'; return result; }
    const x = domainAge.creationDays;
    const a = 2, b = 6;
    const score = Math.floor(60 / (1 + Math.pow(x / (60 * b), a)));
    result.score = score;
    result.triggered = score >= 30;
    result.status = score >= 30 ? 'warn' : 'pass';
    result.detail = `注册于 ${domainAge.registrationDate}（${x} 天前，注册商: ${domainAge.registrar || '未知'}），年龄评分 ${score}/60`;
    return result;
  }

  // 规则七：老域名补偿（防负保护：减分不超过规则六得分）
  static _evaluateRule7(domainAge, currentTotal, rule6Score) {
    const result = { score: 0, triggered: false, status: 'neutral', detail: '' };
    if (!domainAge) { result.detail = '无域名年龄数据，不应用减分'; return result; }
    if (currentTotal < 20) { result.detail = '总分<20，不应用减分'; return result; }
    const x = domainAge.creationDays;
    let deduction = 0;
    if (x >= 730) deduction = 20;
    else if (x >= 180) deduction = Math.floor(20 * (x - 180) / 550);
    deduction = Math.min(deduction, rule6Score); // P1 修复：730天时规则六仅剩约12分，减20会打成负分
    result.score = -deduction;
    result.triggered = deduction > 0;
    result.status = 'pass';
    result.detail = deduction > 0 ? `注册满 ${x} 天，老域名补偿 -${deduction}` : '新域名不减分';
    return result;
  }

  // 规则八：下载链接跨域检测
  static _evaluateRule8(pageText, pageHostname) {
    const result = { score: 0, triggered: false, status: 'neutral', detail: '' };
    if (!pageText) { result.detail = '无页面内容，跳过跨域下载检测'; return result; }
    const pageHost = pageHostname.replace(/^www\./i, '');
    const archiveLinks = pageText.match(/https?:\/\/[^\s<>"]+?(?:\.zip|\.rar|\.7z|\.tar|\.gz|\.exe|\.msi|\.apk)/gi) || [];
    let crossCount = 0, blacklistCount = 0;
    for (const link of archiveLinks) {
      let host;
      try { host = new URL(link).hostname.replace(/^www\./i, ''); } catch (e) { continue; }
      const sameDomain = host === pageHost || pageHost.endsWith('.' + host) || host.endsWith('.' + pageHost);
      if (!sameDomain) {
        crossCount++;
        if (DOWNLOAD_DOMAIN_BLACKLIST.has(host)) blacklistCount++;
      }
    }
    if (blacklistCount > 0) result.score = 30;
    else if (crossCount > 0) result.score = Math.min(10 * crossCount, 20);
    // 中继分发模式检测（2026-09 站群外壳实测：apps-hupu.com.cn 页面内嵌 noah-ssh 中继池）
    // 下载链接不写死在页面，通过 relays.json 分发节点池 + 节点 /api.php 动态下链，静态抓取看不到最终地址
    const relaySignals = [];
    for (const p of RELAY_PATTERNS) {
      if (p.test(pageText)) relaySignals.push(p.source); // p.source 取正则模式文本，不含 / 和 flags
    }
    if (relaySignals.length && result.score < 15) result.score = 15;
    result.triggered = result.score > 0;
    result.status = result.score > 0 ? 'warn' : 'pass';
    result.detail = result.score > 0
      ? `跨域下载链接 ${crossCount} 个${blacklistCount ? `（黑名单命中 ${blacklistCount} 个）` : ''}${relaySignals.length ? `；中继分发信号（${relaySignals.join('、')}）` : ''} (+${result.score})`
      : (archiveLinks.length ? '下载链接均同域' : '未发现压缩包/安装包下载链接');
    return result;
  }

  // 规则九：黑产供应链信号（L3 辅助，不可单独定罪）
  static _evaluateRule9(hostname, domainAge) {
    const result = { score: 0, triggered: false, status: 'pass', detail: '', signals: [] };
    const host = hostname.toLowerCase();
    if (SUSPICIOUS_TLDS.some(tld => host.endsWith(tld))) {
      result.score += 5;
      result.signals.push(`异常TLD ${host.slice(host.lastIndexOf('.'))}`);
    }
    // 站群外壳域模式（2026-09 实测：apps-aisi.com.cn / apps-hupu.com.cn 同伙批量注册）
    if (SHELL_DOMAIN_RE.test(host)) {
      result.score += 5;
      result.signals.push('站群外壳域（修饰词-{品牌}.com.cn 批量注册模式）');
    }
    // 连字符仿冒域（2026-09-04 实测：16 个银狐域中 9 个为此模式）
    if (HYPHEN_SPOOF_RE.test(host)) {
      result.score += 5;
      result.signals.push('连字符仿冒域（修饰词-品牌 .com.cn）');
    }
    // 短主域子域农场（2026-09-04 实测：两字母主域 hl.cn 下挂多个品牌子域）
    if (SHORT_BASE_SUB_RE.test(host)) {
      result.score += 5;
      result.signals.push('短主域子域农场（2字母主域下挂品牌子域）');
    }
    if (domainAge && domainAge.registrar) {
      const r = domainAge.registrar.toLowerCase();
      if (SUSPICIOUS_REGISTRARS.some(s => r.includes(s))) {
        result.score += 5;
        result.signals.push(`高频黑产注册商: ${domainAge.registrar}`);
      }
    }
    // 站群共享 NS（需外部 WHOIS 传入 nameServers；NS 复用 = 同一操作者基础设施）
    if (domainAge && Array.isArray(domainAge.nameServers)) {
      const nsHit = domainAge.nameServers.find(ns =>
        SUSPICIOUS_NAME_SERVERS.some(s => String(ns).toLowerCase().includes(s)));
      if (nsHit) {
        result.score += 5;
        result.signals.push(`站群共享NS: ${nsHit}`);
      }
    }
    // WHOIS 注册邮箱域命中需外部 WHOIS 数据（RDAP 通常不返回），留作扩展点：
    // if (registrantEmail 域名命中 SUSPICIOUS_REGISTRANT_EMAIL_DOMAINS) result.score += 10;
    result.score = Math.min(result.score, 20);
    if (result.score > 0) {
      result.triggered = true;
      result.status = 'warn';
      result.detail = `供应链辅助信号: ${result.signals.join('，')} (+${result.score})，仅作辅助，不可单独定罪`;
    } else {
      result.detail = '无供应链风险信号';
    }
    return result;
  }
}

// ==================== RDAP 域名年龄查询 ====================
async function queryDomainAge(domain) {
  try {
    const resp = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { 'Accept': 'application/rdap+json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    const reg = (data.events || []).find(e => e.eventAction === 'registration');
    if (!reg) return null;
    const days = Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86400000);
    if (days < 0 || days > 7300) return null; // 数据异常防护
    let registrar = '';
    for (const ent of data.entities || []) {
      if ((ent.roles || []).includes('registrar') && ent.vcardArray) {
        const fn = (ent.vcardArray[1] || []).find(f => f[0] === 'fn');
        if (fn) registrar = fn[3] || '';
      }
    }
    return { creationDays: days, registrationDate: reg.eventDate, registrar };
  } catch (e) {
    return null; // RDAP 失败 → 规则六/七/九降级 neutral，不影响其他规则
  }
}

// ==================== 主入口函数 ====================
async function analyzeWebsite(url) {
  let pageContent = '';
  try {
    const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } });
    if (response.ok) pageContent = await response.text();
  } catch (error) { console.log(`获取页面内容失败: ${error.message}`); }
  let hostname;
  try { hostname = new URL(url).hostname; } catch (e) { return { error: '无效的URL格式' }; }
  const domainAge = await queryDomainAge(hostname);
  return ScoringEngine.evaluate(url, pageContent, domainAge);
}


// ==================== CLI 入口 ====================
// 用法：
//   node detect.js <url> [更多url...]
//   node detect.js <url> --json                     输出 JSON（便于程序消费）
//   node detect.js <url> --created=2026-07-28       手动补充注册日期（RDAP 失败时兜底）
//   node detect.js <url> --registrar="北京新网"      手动补充注册商
//   node detect.js <url> --ns=ns1.363.hk,ns2.363.hk 手动补充 NS（逗号分隔，站群共享 NS 信号）
//   node detect.js <url> --no-page                  跳过页面抓取，只做域名级检测
//   node detect.js <url> --use-mcp                  通过 cti-aggregator-mcp 拿数据（推荐）
//   node detect.js <url> --use-mcp --mcp-cmd="python /path/to/server.py"  自定义 MCP 启动命令

const RULE_LABELS = [
  ['rule1', '规则一：域名仿冒检测'],
  ['rule3', '规则三：ICP备案检测'],
  ['rule4', '规则四：链接分析'],
  ['rule5', '规则五：代码工程化检测'],
  ['rule6', '规则六：域名年龄评分'],
  ['rule7', '规则七：老域名补偿'],
  ['rule8', '规则八：跨域下载检测'],
  ['rule9', '规则九：供应链信号'],
];

function formatReport(url, r) {
  const lines = [];
  lines.push('## 网站安全检测报告');
  lines.push('');
  lines.push(`**检测URL**: ${url}`);
  lines.push(`**风险等级**: ${r.riskLevelZh}（${r.riskLevelColor}）`);
  lines.push(`**总得分**: ${r.totalScore}（理论满分 330，红色阈值 100 / 黄色阈值 60）`);
  if (r.shortCircuit) {
    lines.push('');
    // 注意：shortCircuit 字段值本身已含「L1硬证据短路：」前缀，此处不可重复拼接
    lines.push(`> ⚠️ **${r.shortCircuit}** —— 直接判定红色，无需等待其余规则`);
  }
  lines.push('');
  lines.push('### 检测详情');
  lines.push('');
  lines.push('| 规则 | 得分 | 状态 | 详情 |');
  lines.push('|------|------|------|------|');
  for (const [key, label] of RULE_LABELS) {
    const v = r[key];
    if (!v) continue;
    lines.push(`| ${label} | ${v.score} | ${v.statusZh || v.status} | ${v.detail} |`);
  }
  lines.push('');
  lines.push('### 风险评估');
  lines.push('');
  lines.push(`- **风险等级**: ${r.riskLevelColor}（${r.riskLevelZh}）`);
  const advice = {
    danger: '判定为仿冒/恶意站点。建议立即加入 IOC 封堵清单，并排查内部终端是否已有访问记录。',
    warning: '存在多项可疑信号但未达定罪阈值。建议人工复核页面内容与下载链路后再处置。',
    safe: '未检出仿冒信号。若为官方域，建议加入白名单以避免后续重复排查。',
  }[r.riskLevel] || '';
  lines.push(`- **建议**: ${advice}`);
  return lines.join('\n');
}

async function detectOne(url, opts = {}) {
  let pageContent = '';
  if (!opts.noPage) {
    try {
      const response = await fetch(url, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
        signal: AbortSignal.timeout(15000),
      });
      if (response.ok) pageContent = await response.text();
    } catch (error) {
      if (!opts.json) process.stderr.write(`[提示] 页面抓取失败: ${error.message}\n`);
    }
  }
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch (e) {
    return { error: '无效的URL格式' };
  }

  // 数据来源优先级 --use-mcp > 自己 RDAP > 手动参数
  let domainAge = null;
  let dataSource = 'rdap';
  if (opts.useMCP) {
    const mcpData = await mcpInvestigateDomain(hostname, { cmd: opts.mcpCmd });
    if (mcpData) {
      domainAge = mcpData;
      dataSource = 'mcp';
      if (!opts.json) process.stderr.write(`[MCP] 已从 cti-aggregator-mcp 获取结构化数据：${JSON.stringify(mcpData)}\n`);
    } else if (!opts.json) {
      process.stderr.write(`[MCP] 调用失败/字段缺失，降级到 RDAP.org 查询\n`);
    }
  }
  if (!domainAge) domainAge = await queryDomainAge(hostname);
  if (!opts.json) process.stderr.write(`[数据源] ${dataSource}\n`);

  // 手动补齐：MCP/RDAP 字段缺失时，用命令行传入的 WHOIS 情报兜底
  if (opts.created || opts.registrar || opts.ns) {
    domainAge = domainAge || {};
    if (opts.created) {
      const t = new Date(opts.created).getTime();
      if (!isNaN(t)) {
        domainAge.creationDays = Math.max(0, Math.floor((Date.now() - t) / 86400000));
        domainAge.registrationDate = opts.created;
      }
    }
    if (opts.registrar) domainAge.registrar = opts.registrar;
    if (opts.ns) domainAge.nameServers = opts.ns.split(',').map(s => s.trim()).filter(Boolean);
  }
  return ScoringEngine.evaluate(url, pageContent, domainAge);
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(
      '用法: node detect.js <url> [更多url...] [选项]\n' +
      '选项:\n' +
      '  --json                 输出 JSON 而非 Markdown 报告\n' +
      '  --no-page              跳过页面抓取，只做域名级检测\n' +
      '  --use-mcp              通过 cti-aggregator-mcp 拿域龄/注册商/NS/ICP（可选增强，默认走 RDAP）\n' +
      '  --mcp-cmd=CMD          自定义 MCP 启动命令（默认 cti-aggregator-mcp）\n' +
      '  --created=YYYY-MM-DD   手动指定注册日期（MCP/RDAP 失败时兜底）\n' +
      '  --registrar=名称       手动指定注册商\n' +
      '  --ns=ns1,ns2           手动指定 NS 列表（站群共享 NS 信号）\n'
    );
    return;
  }
  const opts = {
    json: argv.includes('--json'),
    noPage: argv.includes('--no-page'),
    useMCP: argv.includes('--use-mcp'),
  };
  for (const a of argv) {
    if (a.startsWith('--created=')) opts.created = a.slice(10);
    if (a.startsWith('--registrar=')) opts.registrar = a.slice(12);
    if (a.startsWith('--ns=')) opts.ns = a.slice(5);
    if (a.startsWith('--mcp-cmd=')) opts.mcpCmd = a.slice(10);
  }
  const urls = argv.filter(a => !a.startsWith('--'));

  const results = [];
  for (const url of urls) {
    const r = await detectOne(url.startsWith('http') ? url : `https://${url}`, opts);
    results.push({ url, result: r });
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(results.map(x => ({ url: x.url, ...x.result })), null, 2) + '\n');
    return;
  }
  const blocks = results.map(x => x.result.error
    ? `## 检测失败\n\n**URL**: ${x.url}\n\n原因: ${x.result.error}`
    : formatReport(x.url, x.result));
  process.stdout.write(blocks.join('\n\n---\n\n') + '\n');
}

if (require.main === module) {
  main().catch(e => {
    process.stderr.write(`执行失败: ${e.message}\n`);
    process.exit(1);
  });
}

module.exports = { ScoringEngine, DomainDatabase, IcpUtils, detectOne, analyzeWebsite, queryDomainAge, formatReport, DOMAIN_DATABASE };
