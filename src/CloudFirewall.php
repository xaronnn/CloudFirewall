<?php if(!defined('BASEPATH')) exit('Direct access not allowed');

namespace CF;

class CloudFirewall {

    private $email;
    private $key;
    private $curl;

    public function __construct($email, $key) {
        $this->email = $email;
        $this->key = $key;
    }

    public function changeSecurityLevel($zone, $value = 'low') {
        return (!$this->checkSecurityLevel($value)) || (empty($zone)) ? false : $this->connect('https://api.cloudflare.com/client/v4/zones/'.$zone.'/settings/security_level', 'PATCH', array('value' => $value));
    }

    public function blockIPv4($value) {
        return (!$this->checkIPv4($value)) ? false : $this->connect('https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules', 'POST', array('mode' => 'block', 'configuration' => array('target' => 'ip', 'value' => $value), 'notes' => 'End in '.date('d.m.Y H:i:s a', time()+300)));
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

    protected function checkIPv4($value) {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) ? true : false;
    }

}
?>