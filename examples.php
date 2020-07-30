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
$firewall->createAccessRule('31.13.37.31', 'block');


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
Parameters: cookieStealBlock(true if you want request ip ban from Cloudflare. default is true.)
*/
$firewall->cookieStealBlock();

/*
Enabling anti floood.
Parameters: antiFlood(requestPerSecond, badRequestChance, badRequestResetInXseconds, banFromCloudflare)
*/
$firewall->antiFlood(2, 3, 5, true);

/*
Get script execution time.
Info: Please write at the bottom of the page.
Usage: echo($firewall->benchmark());
*/
$firewall->benchmark();
?>