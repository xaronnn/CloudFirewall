<?php
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
$firewall->createAccessRule('31.13.37.31', 'block');


/*
Enabling block SQL injection attacks and it will ban from Cloudflare.
*/
$firewall->sqlInjectionBlock();

/*
Enabling block XSS injection attacks and it will ban from Cloudflare.
*/
$firewall->xssInjectionBlock();

/*
Enabling block cookie steal attacks.
*/
$firewall->cookieStealBlock();

/*
Enabling anti flood.
Parameters: antiFlood(requestPerSecond, badRequestChance, badRequestResetInXseconds, banFromCloudflare)
*/
$firewall->antiFlood(2, 3, 5, true);
?>