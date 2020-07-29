# CloudFirewall
Protect your website against bots/spam/flood as using Cloudflare service.

![GitHub stars](https://img.shields.io/github/stars/xaronnn/CloudFirewall)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/xaronnn/CloudFirewall)
![GitHub](https://img.shields.io/github/license/xaronnn/CloudFirewall)
![Discord](https://img.shields.io/discord/729977481242738690)
![GitHub top language](https://img.shields.io/github/languages/top/xaronnn/CloudFirewall)
![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/xaronnn/CloudFirewall)
![GitHub issues](https://img.shields.io/github/issues/xaronnn/CloudFirewall)


# Installation

`composer require xaron/cloudfirewall`

# Examples

```php
require_once('vendor/autoload.php');

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
$firewall->createAccessRule('185.185.185.185', 'challenge');
```

# Requirements

- [x]  PHP >= 7.1.*
- [x]  Curl w/ SSL