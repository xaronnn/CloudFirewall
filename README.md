# CloudFirewall
Protect your website against bots/spam/flood, sql/xss injection attacks as using Cloudflare service.

![GitHub stars](https://img.shields.io/github/stars/0x5841524f4e/CloudFirewall)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/0x5841524f4e0x5841524f4e/CloudFirewall)
![GitHub](https://img.shields.io/github/license/0x5841524f4e/CloudFirewall)
![GitHub top language](https://img.shields.io/github/languages/top/0x5841524f4e/CloudFirewall)
![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/0x5841524f4e/CloudFirewall)
![GitHub issues](https://img.shields.io/github/issues/0x5841524f4e/CloudFirewall)


# Installation

`composer require xaron/cloud-firewall`

# WHMCS Module

`Download: https://github.com/0x5841524f4e/CloudFirewall/raw/master/CloudFirewallWHMCS.rar`

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
