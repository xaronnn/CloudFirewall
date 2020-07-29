<?php
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