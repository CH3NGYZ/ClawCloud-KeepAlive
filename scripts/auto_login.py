#!/usr/bin/env python3
"""
ClawCloud 自动登录脚本
- 等待设备验证批准（30秒）
- 每次登录后自动更新 Cookie
- Telegram 通知
"""

import os
import sys
import time
import base64
import hashlib
import hmac
import struct
import requests
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
CLAW_CLOUD_URL = "https://eu-central-1.run.claw.cloud"
SIGNIN_URL = f"{CLAW_CLOUD_URL}/signin"
DEVICE_VERIFY_WAIT = 30


class Telegram:
    """Telegram 通知"""

    def __init__(self):
        self.token = os.environ.get('TG_BOT_TOKEN')
        self.chat_id = os.environ.get('TG_CHAT_ID')
        self.ok = bool(self.token and self.chat_id)

    def send(self, msg):
        if not self.ok:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                data={"chat_id": self.chat_id,
                      "text": msg, "parse_mode": "HTML"},
                timeout=30
            )
        except:
            pass

    def photo(self, path, caption=""):
        if not self.ok or not os.path.exists(path):
            return
        try:
            with open(path, 'rb') as f:
                requests.post(
                    f"https://api.telegram.org/bot{self.token}/sendPhoto",
                    data={"chat_id": self.chat_id, "caption": caption[:1024]},
                    files={"photo": f},
                    timeout=60
                )
        except:
            pass


class SecretUpdater:
    """GitHub Secret 更新器"""

    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            print("✅ Secret 自动更新已启用")
        else:
            print("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")

    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public

            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }

            # 获取公钥
            r = requests.get(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                headers=headers, timeout=30
            )
            if r.status_code != 200:
                return False

            key_data = r.json()
            pk = public.PublicKey(
                key_data['key'].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())

            # 更新 Secret
            r = requests.put(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                headers=headers,
                json={"encrypted_value": base64.b64encode(
                    encrypted).decode(), "key_id": key_data['key_id']},
                timeout=30
            )
            return r.status_code in [201, 204]
        except Exception as e:
            print(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    """自动登录"""

    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.secret_2fa = os.environ.get('GH_2FA_SECRET')
        self.tg = Telegram()
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0

    def log(self, msg, level="INFO"):
        icons = {"INFO": "ℹ️", "SUCCESS": "✅",
                 "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        self.logs.append(line)

    def generate_totp(self, secret):
        """Generate TOTP code from secret"""
        # 解码base32编码的密钥
        secret = secret.replace(' ', '')
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += '=' * (8 - missing_padding)
        decoded_secret = base64.b32decode(secret.upper())

        # 获取当前时间戳并计算时间计数器
        timestamp = int(time.time())
        time_counter = struct.pack(">Q", timestamp // 30)

        # 生成HMAC-SHA1哈希
        hmac_hash = hmac.new(decoded_secret, time_counter,
                             hashlib.sha1).digest()

        # 动态截断哈希以获得4字节字符串
        offset = hmac_hash[-1] & 0x0F
        truncated_hash = (
            ((hmac_hash[offset] & 0x7F) << 24)
            | ((hmac_hash[offset + 1] & 0xFF) << 16)
            | ((hmac_hash[offset + 2] & 0xFF) << 8)
            | (hmac_hash[offset + 3] & 0xFF)
        )

        # 生成6位数字代码
        totp_code = str(truncated_hash % 1000000).zfill(6)
        return totp_code

    def shot(self, page, name):
        self.n += 1
        f = f"{self.n:02d}_{name}.png"
        try:
            page.screenshot(path=f)
            self.shots.append(f)
        except:
            pass
        return f

    def click(self, page, sels, desc=""):
        for s in sels:
            try:
                el = page.locator(s).first
                if el.is_visible(timeout=3000):
                    el.click()
                    self.log(f"已点击: {desc}", "SUCCESS")
                    return True
            except:
                pass
        return False

    def get_session(self, context):
        """提取 Session Cookie"""
        try:
            for c in context.cookies():
                if c['name'] == 'user_session' and 'github' in c.get('domain', ''):
                    return c['value']
        except:
            pass
        return None

    def save_cookie(self, value):
        """保存新 Cookie"""
        if not value:
            return

        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")

        # 自动更新 Secret
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已保存")
        else:
            # 通过 Telegram 发送
            self.tg.send(f"""🔑 <b>新 Cookie</b>

请更新 Secret <b>GH_SESSION</b>:
<code>{value}</code>""")
            self.log("已通过 Telegram 发送 Cookie", "SUCCESS")

    def wait_device(self, page):
        """等待设备验证"""
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.shot(page, "设备验证")

        self.tg.send(f"""⚠️ <b>需要设备验证</b>

请在 {DEVICE_VERIFY_WAIT} 秒内批准：
1️⃣ 检查邮箱点击链接
2️⃣ 或在 GitHub App 批准""")

        if self.shots:
            self.tg.photo(self.shots[-1], "设备验证页面")

        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 5 == 0:
                self.log(f"  等待... ({i}/{DEVICE_VERIFY_WAIT}秒)")
                url = page.url
                if 'verified-device' not in url and 'device-verification' not in url:
                    self.log("设备验证通过！", "SUCCESS")
                    self.tg.send("✅ <b>设备验证通过</b>")
                    return True
                try:
                    page.reload(timeout=10000)
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass

        if 'verified-device' not in page.url:
            return True

        self.log("设备验证超时", "ERROR")
        self.tg.send("❌ <b>设备验证超时</b>")
        return False

    def handle_2fa(self, page):
        """处理两步验证"""
        self.log("处理两步验证...", "STEP")
        self.shot(page, "2fa_page")

        try:
            page.wait_for_load_state('networkidle', timeout=30000)
            time.sleep(2)

            # GH_2FA_SECRET变量优先级最高
            if self.secret_2fa:
                # 使用Authenticator app (TOTP)
                self.log("使用 Authenticator app 进行2FA验证 (GH_2FA_SECRET已设置)", "STEP")
                return self._handle_totp_2fa(page)
            else:
                # 尝试使用GitHub Mobile
                self.log("使用 GitHub Mobile 进行2FA验证 (GH_2FA_SECRET未设置)", "STEP")
                return self._handle_mobile_2fa(page)
        except Exception as e:
            self.log(f"两步验证过程中出错: {e}", "ERROR")
            return False

    def _handle_totp_2fa(self, page):
        """处理基于TOTP的两步验证"""
        try:
            # 无论首选是什么，只要有GH_2FA_SECRET就优先使用Authenticator app
            self.log("优先使用 Authenticator app 验证方式", "STEP")

            # 查找并点击Authenticator app选项
            auth_app_link_direct = page.locator(
                'a[href="/sessions/two-factor/app"]:has-text("Authenticator app")')
            if auth_app_link_direct.count() > 0 and auth_app_link_direct.first.is_visible():
                self.log("直接点击 Authenticator app 链接", "STEP")
                auth_app_link_direct.first.click()
                time.sleep(3)
                page.wait_for_load_state('networkidle', timeout=30000)
                self.shot(page, "2fa_auth_app_page")
            else:
                more_options_button = page.locator(
                    'button.more-options-two-factor')
                if more_options_button.count() > 0 and more_options_button.first.is_visible():
                    self.log("点击 More options 按钮", "STEP")
                    more_options_button.first.click()
                    time.sleep(2)

                    auth_app_link = page.locator(
                        'a[href="/sessions/two-factor/app"]')
                    if auth_app_link.count() > 0 and auth_app_link.first.is_visible():
                        self.log("点击 Authenticator app 链接", "STEP")
                        auth_app_link.first.click()
                        time.sleep(3)
                        page.wait_for_load_state('networkidle', timeout=30000)
                        self.shot(page, "2fa_auth_app_page")
                    else:
                        self.log("未找到 Authenticator app 链接", "WARN")
                        return False
                else:
                    self.log("未找到 More options 按钮，直接查找2FA输入框", "STEP")

            otp_selectors = [
                'input[name="app_otp"]',
                'input[inputmode="numeric"]',
                'input[autocomplete="one-time-code"]',
                'input[id*="otp"]',
                'input[id*="2fa"]',
                'input[id*="code"]',
                'input[aria-label*="code" i]',
                'input[placeholder*="code" i]',
                'input[placeholder*="authentication" i]'
            ]

            otp_input = None
            for selector in otp_selectors:
                try:
                    otp_input = page.locator(selector).first
                    if otp_input.is_visible(timeout=5000):
                        self.log(f"找到2FA输入框: {selector}", "SUCCESS")
                        break
                except:
                    continue

            if not otp_input:
                self.log("未找到2FA输入框", "ERROR")
                return False

            try:
                code_2fa = self.generate_totp(self.secret_2fa)
                self.log(f"通过GH_2FA_SECRET生成验证码", "STEP")
            except Exception as e:
                self.log(f"生成TOTP验证码失败: {e}", "ERROR")
                return False

            if not code_2fa:
                self.log("无法生成有效的2FA验证码", "ERROR")
                return False

            otp_input.fill(code_2fa)
            self.log("已填入验证码", "STEP")

            self.click(page, [
                'button[type="submit"]:has-text("Verify"), button[type="submit"]:has-text("验证")',
                'button:has-text("Verify"), button:has-text("验证")',
                'button[type="submit"]',
                '.btn-primary',
                'input[type="submit"]'
            ], "提交验证码")

            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.shot(page, "2fa_after_submit")

            flash_error = page.locator(
                '.flash-error:has-text("Two-factor authentication failed")')
            if flash_error.count() > 0 and flash_error.first.is_visible():
                error_text = flash_error.first.text_content().strip()
                self.log(f"两步验证失败: {error_text}", "ERROR")
                return False

            success_indicators = [
                'github.com',
                'claw.cloud'
            ]

            current_url = page.url.lower()
            is_success = any(
                indicator in current_url for indicator in success_indicators) and 'two-factor' not in current_url

            if is_success:
                self.log("两步验证成功, 重定向成功", "SUCCESS")
                return True
            else:
                self.log(f"两步验证失败，当前页面: {page.url}", "WARN")
                return False
        except Exception as e:
            self.log(f"TOTP两步验证过程中出错: {e}", "ERROR")
            return False

    def _click_github_mobile_link(self, page, mobile_link_locator):
        """点击GitHub Mobile链接并处理后续流程"""
        try:
            self.log("点击 GitHub Mobile 链接", "STEP")
            mobile_link_locator.first.click()
            time.sleep(1)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.shot(page, "2fa_mobile_page")
            self.log("已选择GitHub Mobile验证，请在手机上完成验证", "INFO")
            # 发送通知告知用户需要在手机上完成验证
            mobile_digits = self.shot(page, "2fa_mobile_digits")
            self.tg.photo(
                mobile_digits, "📱 需要在手机上完成GitHub验证\n请在GitHub Mobile应用中确认登录请求")

            self.log("等待 GitHub Mobile 验证完成...", "STEP")
            try:
                page.wait_for_url("**claw.cloud**", timeout=60000)
                self.log("检测到跳转到 claw.cloud", "SUCCESS")
                self.shot(page, "redirect_success")
                self.tg.send("✅ <b>两步验证成功</b>\n🔄 <b>重定向成功</b>")
                time.sleep(5)
                return True
            except:
                self.log("60秒内未检测到跳转", "WARN")
                return False
        except Exception as e:
            self.log(f"点击GitHub Mobile链接过程中出错: {e}", "ERROR")
            return False

    def _handle_mobile_2fa(self, page):
        """处理GitHub Mobile两步验证"""
        try:
            # 如果没有设置GH_2FA_SECRET，则使用GitHub Mobile
            self.log("使用 GitHub Mobile 验证方式", "STEP")

            # 查找并点击GitHub Mobile选项
            mobile_link_direct = page.locator(
                'a:has-text("GitHub Mobile"), a:has-text("GitHub手机")')
            if mobile_link_direct.count() > 0 and mobile_link_direct.first.is_visible():
                self.log("直接点击 GitHub Mobile 链接", "STEP")
                return self._click_github_mobile_link(page, mobile_link_direct)
            else:
                # 点击更多选项
                more_options_button = page.locator(
                    'button.more-options-two-factor')
                if more_options_button.count() > 0 and more_options_button.first.is_visible():
                    self.log("点击 More options 按钮", "STEP")
                    more_options_button.first.click()
                    time.sleep(2)

                    # 查找GitHub Mobile选项
                    mobile_link = page.locator(
                        'a:has-text("GitHub Mobile"), a:has-text("GitHub手机")')
                    if mobile_link.count() > 0 and mobile_link.first.is_visible():
                        return self._click_github_mobile_link(page, mobile_link)
                    else:
                        self.log("未找到 GitHub Mobile 链接", "WARN")
                        return False
                else:
                    self.log("未找到 More options 按钮", "WARN")
                    return False

        except Exception as e:
            self.log(f"GitHub Mobile两步验证过程中出错: {e}", "ERROR")
            return False

    def login_github(self, page, context):
        """登录 GitHub"""
        self.log("登录 GitHub...", "STEP")
        self.shot(page, "github_登录页")
        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
            self.log("已输入凭据")
        except Exception as e:
            self.log(f"输入失败: {e}", "ERROR")
            return False
        self.shot(page, "github_已填写")

        time.sleep(1)
        try:
            page.locator(
                'input[type="submit"], button[type="submit"]').first.click()
        except:
            pass
        time.sleep(3)
        page.wait_for_load_state('networkidle', timeout=30000)
        self.shot(page, "github_登录后")
        url = page.url
        self.log(f"当前: {url}")
        # 设备验证
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.shot(page, "验证后")
        # 2FA
        if 'two-factor' in page.url:
            if not self.handle_2fa(page):
                self.log("两步验证失败！", "ERROR")
                self.tg.send("❌ <b>两步验证失败</b>")
                return False
            self.log("两步验证成功！", "SUCCESS")
        # 错误
        try:
            err = page.locator('.flash-error').first
            if err.is_visible(timeout=2000):
                self.log(f"错误: {err.inner_text()}", "ERROR")
                return False
        except:
            pass
        return True

    def oauth(self, page):
        """处理 OAuth"""
        if 'github.com/login/oauth/authorize' in page.url:
            self.log("处理 OAuth...", "STEP")
            self.shot(page, "oauth")
            self.click(page, ['button[name="authorize"]',
                       'button:has-text("Authorize")'], "授权")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)

    def wait_redirect(self, page, wait=60):
        """等待重定向"""
        self.log("等待重定向...", "STEP")
        for i in range(wait):
            url = page.url
            if 'claw.cloud' in url and 'signin' not in url.lower():
                self.log("重定向成功！", "SUCCESS")
                return True
            if 'github.com/login/oauth/authorize' in url:
                self.oauth(page)
            time.sleep(1)
            if i % 10 == 0:
                self.log(f"  等待... ({i}秒)")
        self.log("重定向超时", "ERROR")
        return False

    def keepalive(self, page):
        """保活"""
        self.log("保活...", "STEP")
        for url, name in [(f"{CLAW_CLOUD_URL}/", "控制台"), (f"{CLAW_CLOUD_URL}/apps", "应用")]:
            try:
                page.goto(url, timeout=30000)
                page.wait_for_load_state('networkidle', timeout=15000)
                self.log(f"已访问: {name}", "SUCCESS")
                time.sleep(2)
            except:
                pass
        self.shot(page, "完成")

    def notify(self, ok, err=""):
        if not self.tg.ok:
            return

        msg = f"""<b>🤖 ClawCloud 自动登录</b>

<b>状态:</b> {"✅ 成功" if ok else "❌ 失败"}
<b>用户:</b> {self.username}
<b>时间:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"""

        if err:
            msg += f"\n<b>错误:</b> {err}"

        msg += "\n\n<b>日志:</b>\n" + "\n".join(self.logs[-6:])

        self.tg.send(msg)

        if self.shots:
            if not ok:
                for s in self.shots[-3:]:
                    self.tg.photo(s, s)
            else:
                self.tg.photo(self.shots[-1], "完成")

    def run(self):
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录")
        print("="*50 + "\n")

        self.log(f"用户名: {self.username}")
        self.log(f"Session: {'有' if self.gh_session else '无'}")
        self.log(f"密码: {'有' if self.password else '无'}")
        self.log(f"2FA Secret: {'有' if self.secret_2fa else '无'}")

        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)

        with sync_playwright() as p:
            # 直接使用环境变量，GitHub Actions已提供默认值
            user_data_dir = os.environ.get('BROWSER_USER_DATA_DIR')
            user_agent = os.environ.get('CUSTOM_USER_AGENT')
            is_headless = os.environ.get(
                'BROWSER_HEADLESS', 'true').lower() == 'true'

            # 使用launch_persistent_context来支持用户数据目录
            context = p.chromium.launch_persistent_context(
                user_data_dir=user_data_dir,
                headless=is_headless,
                args=['--no-sandbox'],
                user_agent=user_agent
            )
            page = context.new_page()

            try:
                # 预加载 Cookie
                if self.gh_session:
                    try:
                        context.add_cookies([
                            {'name': 'user_session', 'value': self.gh_session,
                                'domain': 'github.com', 'path': '/'},
                            {'name': 'logged_in', 'value': 'yes',
                                'domain': 'github.com', 'path': '/'}
                        ])
                        self.log("已加载 Session Cookie", "SUCCESS")
                    except:
                        self.log("加载 Cookie 失败", "WARN")

                # 1. 访问 ClawCloud
                self.log("步骤1: 打开 ClawCloud", "STEP")
                page.goto(SIGNIN_URL, timeout=60000)
                page.wait_for_load_state('networkidle', timeout=30000)
                time.sleep(2)
                self.shot(page, "clawcloud")

                if 'signin' not in page.url.lower():
                    self.log("已登录！", "SUCCESS")
                    self.keepalive(page)
                    # 提取并保存新 Cookie
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    self.notify(True)
                    print("\n✅ 成功！\n")
                    return

                # 2. 点击 GitHub
                self.log("步骤2: 点击 GitHub", "STEP")
                if not self.click(page, [
                    'button:has-text("GitHub")',
                    'a:has-text("GitHub")',
                    '[data-provider="github"]'
                ], "GitHub"):
                    self.log("找不到按钮", "ERROR")
                    self.notify(False, "找不到 GitHub 按钮")
                    sys.exit(1)

                time.sleep(3)
                page.wait_for_load_state('networkidle', timeout=30000)
                self.shot(page, "点击后")

                url = page.url
                self.log(f"当前: {url}")

                # 3. GitHub 登录
                self.log("步骤3: GitHub 认证", "STEP")

                if 'github.com/login' in url or 'github.com/session' in url:
                    if not self.login_github(page, context):
                        self.shot(page, "登录失败")
                        self.notify(False, "GitHub 登录失败")
                        sys.exit(1)
                elif 'github.com/login/oauth/authorize' in url:
                    self.log("Cookie 有效", "SUCCESS")
                    self.oauth(page)

                # 4. 等待重定向
                self.log("步骤4: 等待重定向", "STEP")
                if not self.wait_redirect(page):
                    self.shot(page, "重定向失败")
                    self.notify(False, "重定向失败")
                    sys.exit(1)

                self.shot(page, "重定向成功")

                # 5. 验证
                self.log("步骤5: 验证", "STEP")
                if 'claw.cloud' not in page.url or 'signin' in page.url.lower():
                    self.notify(False, "验证失败")
                    sys.exit(1)

                # 6. 保活
                self.keepalive(page)

                # 7. 提取并保存新 Cookie
                self.log("步骤6: 更新 Cookie", "STEP")
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)
                else:
                    self.log("未获取到新 Cookie", "WARN")

                self.notify(True)
                print("\n" + "="*50)
                print("✅ 成功！")
                print("="*50 + "\n")

            except Exception as e:
                self.log(f"异常: {e}", "ERROR")
                self.shot(page, "异常")
                import traceback
                traceback.print_exc()
                self.notify(False, str(e))
                sys.exit(1)
            finally:
                context.close()


if __name__ == "__main__":
    AutoLogin().run()
