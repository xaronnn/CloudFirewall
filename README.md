# CloudFirewall
Protect your website against bots/spam/flood as using Cloudflare service.


![GitHub stars](https://img.shields.io/github/stars/xaronnn/CloudFirewall)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/xaronnn/CloudFirewall)
![GitHub](https://img.shields.io/github/license/xaronnn/CloudFirewall)
![Discord](https://img.shields.io/discord/729977481242738690)
![GitHub top language](https://img.shields.io/github/languages/top/xaronnn/CloudFirewall)
![CodeFactor Grade](https://img.shields.io/codefactor/grade/github/xaronnn/CloudFirewall)
![GitHub issues](https://img.shields.io/github/issues/xaronnn/CloudFirewall)

```php
define('BASEPATH', true);
require_once('./CloudFirewall.php');

/*
Init CloudFirewall class.
*/
$firewall = new CloudFirewall('xaron@gmail.com', 'xaron12345');


/*
Change security level.
*/
$firewall->changeSecurityLevel('zone id', 'medium');


/*
Ban IP address.
*/
$firewall->blockIPv4('31.13.37.31');
```