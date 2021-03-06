# CloudFirewall
Protect your website against bots/spam/flood, sql/xss injection attacks as using Cloudflare service.

![GitHub stars](https://img.shields.io/github/stars/xaronnn/CloudFirewall)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/xaronnn/CloudFirewall)
![GitHub](https://img.shields.io/github/license/xaronnn/CloudFirewall)
![Discord](https://img.shields.io/discord/729977481242738690)
![GitHub top language](https://img.shields.io/github/languages/top/xaronnn/CloudFirewall)
![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/xaronnn/CloudFirewall)
![GitHub issues](https://img.shields.io/github/issues/xaronnn/CloudFirewall)


# Installation

`composer require xaron/cloud-firewall`

# WHMCS Module

`Download: https://github.com/xaronnn/CloudFirewall/raw/master/CloudFirewallWHMCS.rar`

`Export files to your main WHMCS directory.`

# Examples

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';

use CF\CloudFirewall;

/*
Init CloudFirewall class.
*/
$firewall = new CloudFirewall('email_address', 'global_api_key', 'zone_id (Not required if already set in function parameter)');

/*
Change security level.
Actions: [essentially_off, low, medium, high, under_attack]
*/
$firewall->changeSecurityLevel('medium', 'zone_id (Not required if already set in constructor)');

/*
Create access rule.
Actions: [block, challenge, whitelist, js_challenge]
*/
$firewall->createAccessRule('31.13.37.31', 'challenge');

/*
Enabling block SQL injection attacks and it will ban from Cloudflare.
Parameters: sqlInjectionBlock(true if you want request ip ban from Cloudflare. default is true.)
*/
$firewall->sqlInjectionBlock();

/*
Enabling block XSS injection attacks and it will ban from Cloudflare.
Parameters: xssInjectionBlock(true if you want request ip ban from Cloudflare. default is true.)
*/
$firewall->xssInjectionBlock();

/*
Enabling block cookie steal attacks.
Parameters: cookieStealBlock(true if you want request ip ban from Cloudflare. default is false.)
*/
$firewall->cookieStealBlock();

/*
Enabling anti flood.
Parameters: antiFlood(requestPerSecond, badRequestChance, badRequestResetInXseconds, banFromCloudflare)
*/
$firewall->antiFlood(1, 3, 5, true);

/*
Get script execution time.
Info: Please write at the bottom of the page.
Usage: echo($firewall->benchmark());
*/
$firewall->benchmark();
```

# Requirements

- [x]  PHP >= 7.1.*
- [x]  cURL extension
- [x]  OpenSSL extension