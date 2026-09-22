# MyAdBlockRules v3：两个指定源的保守 Hosts 合并

输出地址保持为 rules/adblockhosts.txt。仅使用 Python 3.12 标准库，每8小时自动更新。
这不是完整 AdGuard 引擎，不能承诺零误杀，也不保留网页元素隐藏、请求类型或路径匹配效果。

## 这版解决了什么

- ABP、Hosts、裸域名列表按明确类型分别解析；ABP 中的裸字符串绝不当成域名。
- 所有带 # 的 ABP 元素/脚本规则都跳过，不会把所在网站封锁。
- 支持纯域名拦截以及 $important 域名规则；对于例外冲突采用“放行优先”，不声称完全复刻 AdGuard 优先级。
- 可识别目标域名的网络例外（包括路径/条件例外）保守扩展为该域名及子域名放行。可能减少拦截，优先保证可用性。
- 支持匹配规范化规则键的 $badfilter 禁用。复杂的部分作用域禁用并非完整实现。
- 预处理条件块整块跳过，不猜测客户端环境；格式不平衡则失败。
- 未识别的复杂例外会在 stats.json 的 unresolved_exceptions 中计数；它们的语义未保留，仍可能存在误杀。遇到误杀使用本地白名单，必要时改用原生 AdGuard 规则。
- 拒绝空响应、HTML、零有效域名、无效配置；任一源失败即停止发布。
- 每个源设置最小条数，同版本连续构建时，单源或最终条数减少超过25%或增加超过50%会停止发布。
- 最多3次下载尝试、30秒网络超时、20MiB响应上限；任务最多10分钟。
- 所有解析校验通过后才写文件。GitHub 对两个输出文件一次提交；本地两个文件不是跨文件事务，磁盘故障时不要手动发布。

## 父子域名压缩：Hosts 不使用

0.0.0.0 example.com 不会自动封锁 ads.example.com。
因此保留上游明确列出的父子域名，仅删除完全相同的重复项。不要为了条数更小删除子域名。
ABP 的 ||example.com^ 覆盖子域名，而 Hosts 不具备此能力，转换必然有覆盖损失。
如果以后需要 DOMAIN-SUFFIX 等格式，应单独设计输出，不能从 Hosts 列表直接扩大匹配范围。

## 配置两个订阅源

sources.txt 每行格式是“类型 最小有效域名数 HTTPS地址”，用空格分隔：

```text
abp 30000 https://raw.githubusercontent.com/damengzhu/abpmerge/refs/heads/main/abpmerge.txt
hosts 500 https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-hosts.txt
```

支持类型 abp、hosts、domains。旧版“每行只有URL”不再支持，升级务必覆盖 sources.txt。
阈值是防异常保护，不是预计条数。上游合法大改也可能触发保护，需人工核对。

## 黑白名单

- blocklist.txt：每行一个精确域名，不支持通配符；可覆盖上游例外。
- allowlist.txt：example.com 只放行该域名；*.example.com 在本项目中表示放行该域名及所有子域名。
- 本地 allowlist 优先级最高。上游例外对两个源的合并结果全局生效。
- 修改后手动运行 Actions。请保留自己原有的黑白名单，不要用包里的空模板覆盖。

## 新建 GitHub 仓库：电脑网页教程

1. 登录 https://github.com/new ，仓库名填写 MyAdBlockRules，选择 Public。
2. 点击 Create repository，然后点击 uploading an existing file。
3. 解压压缩包，上传里面的内容，不要上传ZIP本身，也不要套多一层文件夹。
4. 必须包括 .github/workflows/update.yml、build.py、sources.txt、tests/、rules/、README.md、黑白名单文件。
5. 点击 Commit changes。确认默认分支为 main。
6. 如果 .github 上传遗漏，用 Add file → Create new file，文件名填 .github/workflows/update.yml，再从本地复制内容保存。
7. 点击 Actions → Update adblock hosts → Run workflow → Run workflow。
8. 等绿色对勾后，查看 rules/adblockhosts.txt 和 rules/stats.json。
9. 推送权限报错时，检查 Settings → Actions → General → Workflow permissions。组织策略或分支保护可能另有限制，不要擅自关闭保护。

## 已有仓库升级

上传覆盖 build.py、sources.txt、tests/test_build.py、.github/workflows/update.yml、
rules/adblockhosts.txt、rules/stats.json、README.md；不要覆盖已有自定义黑白名单。
如果升级时保留自定义名单，上传包内输出只是基线，需立即手动运行重新生成。
本次 v3 首次迁移不比较旧算法的相对条数，但仍执行单源最小数量保护；后续 v3 使用包内/上次成功统计作基线。

## 订阅地址

将下方用户名和仓库名换成实际值（以下按 Ixin1123/MyAdBlockRules）：

```text
https://raw.githubusercontent.com/Ixin1123/MyAdBlockRules/main/rules/adblockhosts.txt
https://gcore.jsdelivr.net/gh/Ixin1123/MyAdBlockRules@main/rules/adblockhosts.txt
https://cdn.jsdelivr.net/gh/Ixin1123/MyAdBlockRules@main/rules/adblockhosts.txt
```

CDN可能缓存旧内容；先用 Raw 地址检查输出，再等待客户端/CDN更新。
Hosts格式并非适用于所有订阅入口，应导入支持Hosts的拦截工具，不要当作完整浏览器过滤规则。

## 查看构建报告

rules/stats.json 包含源地址、类型、内容SHA-256、候选数量、例外数量、每类规则计数、
上游例外删除数量与最终输出数量。源总行数等于各分类计数之和，域名数与规则行数不一定相等。
SHA变化可能仅来自上游注释或时间戳，因此统计文件变化不代表域名一定变化。

## 异常与恢复

网络或数量校验失败时 Actions 应显示红叉，旧的已提交规则继续可用。先看日志，不要反复绕过保护。
确认上游确实大规模修改后，可在本地执行 python build.py --accept-large-change，然后提交两个输出；
该参数只跳过相对变化阈值，不跳过空内容、最低条数等校验。若需降低单源最低数量，先核对上游实际内容。
工作流不自动合并推送冲突；运行期间编辑仓库可能导致推送失败，重新运行即可。
定时任务运行于默认分支，可能延迟；GitHub可能暂停长期无活动公开仓库的定时任务，需在Actions检查并重新启用。
本包没有访问或部署你的 GitHub 仓库，最终权限与运行结果以你仓库第一次手动运行日志为准。

## 本地测试

```sh
python -m unittest discover -s tests -v
python build.py
```

## 来源与许可

规则来源：
- https://github.com/damengzhu/abpmerge
- https://github.com/TG-Twilight/AWAvenue-Ads-Rule

包内MIT许可仅适用于本项目自写脚本和说明，不替代上游规则的许可。
分发生成规则前应查阅并遵守各上游当前许可和署名要求；本项目不授予上游规则额外权利。
