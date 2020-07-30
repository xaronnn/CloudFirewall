<?php

namespace CF;

class CloudFirewall {

    private $email;
    private $key;
    private $zone;
    private $curl;
    private $debug;

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
        if($this->checkSecurityLevel($value)) {
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

    /**
     * Enabling block SQL injection attacks.
     *
     * @return none.
     */
    public function sqlInjectionBlock() {
        foreach ($_GET as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_GET", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_GET", $key);
			}
        }
        foreach ($_POST as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_POST", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_POST", $key);
			}
        }
        foreach ($_COOKIE as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_COOKIE", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_COOKIE", $key);
			}
		}
    }

    /**
     * Enabling block XSS injection attacks.
     *
     * @return none.
     */
    public function xssInjectionBlock() {
        foreach ($_GET as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
                    $this->xssCheck($sub_value, "GET", $sub_key);
                    $this->htmlCheck($sub_value, "GET", $sub_key);
				}
			} else {
                $this->xssCheck($value, "GET", $key);
                $this->htmlCheck($value, "GET", $key);
			}
        }
        foreach ($_POST as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
                    $this->xssCheck($sub_value, "POST", $sub_key);
                    $this->htmlCheck($sub_value, "POST", $sub_key);
				}
			} else {
                $this->xssCheck($value, "POST", $key);
                $this->htmlCheck($value, "POST", $key);
			}
        }
        foreach ($_COOKIE as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
                    $this->xssCheck($sub_value, "COOKIE", $sub_key);
                    $this->htmlCheck($sub_value, "COOKIE", $sub_key);
				}
			} else {
                $this->xssCheck($value, "COOKIE", $key);
                $this->htmlCheck($value, "COOKIE", $key);
			}
		}
    }

    /**
     * Enabling block steal cookie attacks.
     *
     * @return none.
     */
    public function cookieStealBlock() {
		if (isset($_SESSION)) {
            if (!isset($_SESSION['CloudFirewall-Client-IP'])) {
                $_SESSION['CloudFirewall-Client-IP'] = $_SERVER[($_SERVER['HTTP_CF_CONNECTING_IP'] ? 'HTTP_CF_CONNECTING_IP' : 'REMOTE_ADDR')];
            } else {
                if ($_SESSION['CloudFirewall-Client-IP'] != $_SERVER[($_SERVER['HTTP_CF_CONNECTING_IP'] ? 'HTTP_CF_CONNECTING_IP' : 'REMOTE_ADDR')]) {
                    header('HTTP/1.0 403 Forbidden');
                    session_destroy();
                    die();
                }
            }
        }
	}

    /**
     * Enable debug mode.
     *
     * @return none.
     */
    public function debug($debug = false) {
        $this->debug = $debug;
    }

    private function xssCheck($value, $method, $displayName) {
		$replace = array("<3" => ":heart:");
		foreach ($replace as $key => $value_rep) {
			$value = str_replace($key, $value_rep, $value);
		}
		$badWords = $this->getVulnTypeData('XSS');
		foreach ($badWords as $badWord) {
			if (strpos(strtolower($value), strtolower($badWord)) !== false) {
			    header('HTTP/1.0 403 Forbidden');
                //echo json_encode(array('error' => true, 'message' => 'XSS injection detected, request is terminated and request IP address has banned from Cloudflare.', 'data' => array('word' => $badWord, 'request_method' => $method)));
                $this->createAccessRule($this->getIP(), 'block');
                die();
			}
		}
	}

    private function sqlCheck($value, $method, $displayName) {
		$replace = array("can't" => "can not", "don't" => "do not");
		foreach ($replace as $key => $value_rep) {
			$value = str_replace($key, $value_rep, $value);
		}
		$badWords = $this->getVulnTypeData('SQL');
		foreach ($badWords as $badWord) {
			if (strpos(strtolower($value), strtolower($badWord)) !== false) {
                header('HTTP/1.0 403 Forbidden');
                //echo json_encode(array('error' => true, 'message' => 'SQL injection detected, request is terminated and request IP address has banned from Cloudflare.', 'data' => array('word' => $badWord, 'request_method' => $method)));
                $this->createAccessRule($this->getIP(), 'block');
                die();
            }
		}
    }

    private function htmlCheck($value, $method, $displayName) {
		if ($this->is_html(strtolower($value)) !== false) {
			header('HTTP/1.0 403 Forbidden');
            //echo json_encode(array('error' => true, 'message' => 'XSS injection detected, request is terminated and request IP address has banned from Cloudflare.', 'data' => array('word' => $badWord, 'request_method' => $method)));
            $this->createAccessRule($this->getIP(), 'block');
            die();
		}
    }
    
    protected function is_html($string) {
		return ($string != strip_tags($string) ? true : false);
	}

    protected function getIP() {
        return ($_SERVER['HTTP_CF_CONNECTING_IP'] ? $_SERVER['HTTP_CF_CONNECTING_IP'] : $_SERVER['REMOTE_ADDR']);
    }

    private function arrayFlatten(array $array) {
	    $flatten = array();
	    array_walk_recursive($array, function($value) use(&$flatten) {
	        $flatten[] = $value;
	    });
	    return $flatten;
	}

    protected function getVulnTypeData($type) {
        if($type && in_array($type, array('SQL', 'XSS'))) {
            $vuln['SQL'] = array(
                "'",
                '´',
                'SELECT FROM',
                'SELECT * FROM',
                'ONION',
                'union',
                'UNION',
                'TRUNCATE TABLE',
                'INSERT INTO',
                'UDPATE users SET',
                'WHERE username',
                'DROP TABLE',
                '0x50',
                'mid((select',
                'union(((((((',
                'concat(0x',
                'concat(',
                'OR boolean',
                'or HAVING',
                "OR '1",
                '0x3c62723e3c62723e3c62723e',
                '0x3c696d67207372633d22',
                '+#1q%0AuNiOn all#qa%0A#%0AsEleCt',
                'unhex(hex(Concat(',
                'Table_schema,0x3e,',
                '0x00',
                '0x08',
                '0x09',
                '0x0a',
                '0x0d',
                '0x1a',
                '0x22',
                '0x25',
                '0x27',
                '0x5c',
                '0x5f'
            );
            $vuln['XSS'] = array('<img',
                'img>',
                'style=',
                '<table',
                '<td',
                '<tr',
                '<b',
                '<font',
                '<br',
                '</br',
                '<a ',
                'href',
                '<h',
                '<image',
                'document.cookie',
                'onerror()',
                'script>',
                '<script',
                'alert(',
                'window.',
                'String.fromCharCode(',
                'javascript:',
                'onmouseover="',
                '<BODY onload',
                '<style',
                'svg onload',
                'onclick='
            );
            return $vuln[$type];
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
    }

    protected function checkSecurityLevel($value) {
        return (in_array($value, array('essentially_off', 'low', 'medium', 'high', 'under_attack'))) ? true : false;
    }
    protected function checkAccessRule($value) {
        return (in_array($value, array('block', 'challenge', 'whitelist', 'js_challenge'))) ? true : false;
    }

    protected function checkIPv4($value) {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) ? true : false;
    }

    protected function checkIPv6($value) {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) ? true : false;
    }

    protected function checkIP($value) {
        return (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) ? true : false;
    }

}
?>