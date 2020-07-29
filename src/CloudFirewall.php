<?php

namespace CF;

class CloudFirewall {

    private $email;
    private $key;
    private $zone;
    private $curl;

    /**
     * CloudFirewall constructor.
     *
     * @param string $email The your Cloudflare email address.
     * @param string $key The your Cloudflare API key.
     * @param string $zone The your Cloudflare zone.
     */
    public function __construct($email, $key, $zone = null) {
        $this->email = $email;
        $this->key = $key;
        $this->zone = $zone;
    }

    /**
     * Changes security level on your zone.
     *
     * @param string $value The security levels [essentially_off, low, medium, high, under_attack].
     * @param string $zone The zone id.
     * @return mixed Bool False if request is not responded. JSON if request success.
     */
    public function changeSecurityLevel($value = 'low', $zone = null) {
        if($this->checkSecurityLevel($vlaue)) {
            if($zone) {
                return $this->connect('https://api.cloudflare.com/client/v4/zones/'.$zone.'/settings/security_level', 'PATCH', array('value' => $value));
            } else {
                return $this->connect('https://api.cloudflare.com/client/v4/zones/'.$this->zone.'/settings/security_level', 'PATCH', array('value' => $value));
            }
        } else {
            return false;
        }
    }

    /**
     * Create rule to specified IP address with an action.
     *
     * @param string $value The IP(v4/v6) address.
     * @param string $action The action [block, challenge, whitelist, js_challenge].
     * @return mixed Bool False if request is not responded. JSON if request success.
     */
    public function createAccessRule($value, $action) {
        if($this->checkIP($value) && $this->checkAccessRule($action)) {
            return $this->connect('https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules', 'POST', array('mode' => $action, 'configuration' => array('target' => ($this->checkIPv4($value) ? 'ip' : ($this->checkIPv4($value) ? 'ip6' : null)), 'value' => $value), 'notes' => 'Created by CloudFirewall'));
        } else {
            return false;
        }
    }

    protected function connect($url, $request, $fields) {
        $this->curl = curl_init();
        curl_setopt($this->curl, CURLOPT_URL, $url);
        curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($this->curl, CURLOPT_SSL_VERIFYPEER, false);
        if($request == 'POST') {
            curl_setopt($this->curl, CURLOPT_POST, 1);
        }else{
            curl_setopt($this->curl, CURLOPT_CUSTOMREQUEST, $request);
        }
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, json_encode($fields));
        curl_setopt($this->curl, CURLOPT_HTTPHEADER, array('X-Auth-Email: '.$this->email, 'X-Auth-Key: '.$this->key, 'Content-Type: application/json'));
        return curl_exec($this->curl);
        curl_close($this->curl);
    }

    protected function checkSecurityLevel($value) {
        return (in_array($value, array('essentially_off', 'low', 'medium', 'high', 'under_attack'))) ? true : false;
    }
    protected function checkAccessRule($value) {
        return (in_array($value, array('essentialblockly_off', 'challenge', 'whitelist', 'js_challenge'))) ? true : false;
    }

    protected function checkIPv4($value) {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) ? true : false;
    }

    protected function checkIPv6($value) {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) ? true : false;
    }

    protected function checkIP($value) {
        return (filter_var($value, FILTER_VALIDATE_IP)) ? true : false;
    }

}
?>