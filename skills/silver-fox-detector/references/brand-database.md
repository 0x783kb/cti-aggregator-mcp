# 品牌域名数据库

> Silver Fox Detector 的仿冒判定底座，共 132 条，按「仿冒对象」颗粒度建条目。
> 主文件 SKILL.md 不含本表——**只在需要时读它**，避免 4.6K token 常驻上下文。

## 什么时候读这个文件

- 排查误报：某域被判仿冒，想确认命中了哪条品牌条目
- 确认覆盖：某品牌是否已收录（未收录则仿冒域会漏检）
- 新增条目：要往里加品牌时，先读「新增条目的规范」一节
- 品牌关键词设计：需要理解短关键词的长度约束时

## 颗粒度原则（重要）

**按「仿冒对象」独立建条目，不按公司归并**。例如网易系必须拆成网易 / 有道 / UU 加速器 / 云音乐 四条，不能合并成一条「网易」——否则统计仿冒分布时无法定位真正的受害品牌。

同理腾讯系拆成 QQ / TIM / 腾讯会议 / QQ邮箱 / 腾讯游戏 等，各自独立。

## 数据库定义

```javascript
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
```

## 供应链与下载信号常量

```javascript
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
```

## 新增条目的规范

1. **先核实官方域名**——必须搜索确认，不能凭印象。教训：DeepSeek 条目曾漏写主域 `deepseek.com`（只写了 `chat.deepseek.com`），导致官方主域被自己的引擎判成仿冒。
2. **分销商 / 代理站不算官方域**。例：`ocam-soft.com.cn` 自称 oCam 官方，实为国内分销，**未列入** `officialDomains`，否则会误豁免。
3. **短关键词慎加**。规则 A（域名段精确匹配）无长度门槛，2-4 字符关键词会大面积误伤：
   - 爱思助手条目刻意**不加** `i4`（2 字符）——否则 BMW i4、i4.io 全误报
   - `aisi`（4 字符）已收录，代价是 `aisi.io` 这类海外无关域会判 warning（不定罪，人工复核兜底）
4. **关键词按「中文名 + 官方英文名 + 拼音变体 + 常见拼写错误」四层设计**，例如爱思助手：`['爱思助手', 'i4tools', 'i4cn', 'aisizhushou', 'aisi']`。
5. **typosquat 依赖正确拼写**——编辑距离匹配（规则 D）需要先有正确拼写的条目才能算出距离。例：`mindmoster.com.cn` 是靠距 `mindmaster` 距离 1 抓到的。

## 已知权衡

| 权衡点 | 说明 |
|---|---|
| 短关键词误伤 | `aisi`（4 字符）会把恰好叫 aisi 的海外域判 warning；warning 不触发封堵，保留锚点防漏报 |
| 外国品牌 ICP 豁免 | 部分外国品牌域名在 `ICP_EXEMPT_DOMAINS` 中，避免「无 ICP」误判 |
