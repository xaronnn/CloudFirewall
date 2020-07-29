<?php
require_once('vendor/autoload.php');

use CF\CloudFirewall;

/*
Init CloudFirewall class.
*/
$firewall = new CloudFirewall('xaron@emailn.de', '4db180af1da0d37ddd9fc0e36ea442bf19f5a', 'zone_id (Not required if already set in function parameter)');

/*
Change security level.
*/
$firewall->changeSecurityLevel('medium', 'zone_id (Not required if already set in constructor)');

/*
Create access rule.
*/
$firewall->createAccessRule('185.185.185.185', 'challenge');