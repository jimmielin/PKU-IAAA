<?php
/**
 * @package         com.jimmielin.pku_iaaa
 * @author          Jimmie Lin <myself@jimmielin.me>
 * @copyright       (c) 2016 Jimmie Lin, All Rights Reserved.
 * @license         MIT License
 *
 * Peking University IAAA Wrapper (Internal Authenticator)
 * Functional as of 2016.03.11
 */
namespace PKU;

class IAAA {
    /**
     * Error ID kept internally, for the previous request taken.
     * 0  = no error
     * 9  = network error
     * 1 = authentication failed
     */
    private $errorID = 0;

    /**
     * IAAA Simple Authentication.
     * @param       username   String    the username (student/faculty n#, pku email)
     * @param       password   String    password for the above account.
     * @param       method     String    proxy / iaaa
     * @return      bool
     * 
     * Note: While the proxy method is faster as it does not go through IAAA Web
     * (which itself needs to be accessed through a proxy when out-of-PKU)
     * According to ITS documentation, proxies are not supported in 162.105.* IP ranges
     * (covering most wired areas in PKU, but not Wireless), and may result in undefined
     * behavior.
     * Additionally, PKU Alumni who are no longer STD/FAC accounts (post-leave) are not
     * authenticated via either proxy or vpn, and the wrapper will return false even if
     * authentication is successful. There is no known method for circumvention, not without
     * providing a hard-coded STD account and use IAAA / Dean as alternate auth methods.
     */
    public function verify_iaaa($username, $password, $method = "proxy") {
        switch($method) {
            case "proxy":
                return $this->_verify_iaaa_proxy($username, $password);
            break;

            case "iaaa":
            default:
                return $this->_verify_iaaa_web($username, $password);
        }
    }

    /**
     * IAAA Proxy Authentication.
     * @param       username   String    the username (student/faculty n#, pku email)
     * @param       password   String    password for the above account.
     * @return      bool
     */
    private function _verify_iaaa_proxy($username, $password) {
        $cConn = curl_init();
        curl_setopt($cConn, CURLOPT_URL, "http://elective.pku.edu.cn"); // use a known address that does not resolve out of PKU
        curl_setopt($cConn, CURLOPT_PROXY, "proxy.pku.edu.cn:8080");
        curl_setopt($cConn, CURLOPT_PROXYUSERPWD, $username . ":" . $password);
        curl_setopt($cConn, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($cConn, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($cConn, CURLOPT_HEADER, true);
        $sResult = curl_exec($cConn);

        if(curl_errno($cConn)) {
            $this->errorID = 9; // network error
            return false;
        }

        if(preg_match('/407 Proxy Authentication Required/siu', $sResult)) {
            $this->errorID = 1; // user authentication failed
            return false;
        }

        $this->errorID = 0; // success
        return true;

        curl_close($cConn);
    }

    /**
     * IAAA Web (Direct) Authentication.
     * @param       username   String    the username (student/faculty n#, pku email)
     * @param       password   String    password for the above account.
     * @param       inPKU      Bool      are we in PKU 162.105.* IP range? If yes then bypass proxy.
     * @return      array                array of information for the student -- read directly from portal.
     *
     * This logs into the portal and obtains a set of information on the student
     * after the log-in. We use cURL cookies to perform two sets of requests, one to
     * authenticate via IAAA-Portal (proxy-based), the next one to pull the info over.
     */
    private function _verify_iaaa_web($username, $password, $inPKU = true) {
        // from portal.pku.edu.cn/portal2013/login.jsp, window.location.href = () can be preg-matched for safety
        // the response from https://iaaa.pku.edu.cn/iaaa/login.do is actually a JSON response, cool.
        $iaaa_target = "https://iaaa.pku.edu.cn/iaaa/oauthlogin.do";
        $cConn = curl_init();
        curl_setopt($cConn, CURLOPT_URL, $iaaa_target);
        if(!$inPKU) {
            curl_setopt($cConn, CURLOPT_PROXY, "proxy.pku.edu.cn:8080");
            curl_setopt($cConn, CURLOPT_PROXYUSERPWD, $username . ":" . $password);
        }
        curl_setopt($cConn, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($cConn, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($cConn, CURLOPT_SSL_VERIFYPEER, false); // TODO @jimmielin: match with PKU SSL cert to pervent MITM
        curl_setopt($cConn, CURLOPT_HEADER, false);
        curl_setopt($cConn, CURLINFO_HEADER_OUT, true);
        curl_setopt($cConn, CURLOPT_POSTFIELDS, "appid=portal&userName={$username}&password={$password}&randCode=验证码&smsCode=短信验证码&redirUrl=http://portal.pku.edu.cn/portal2013/login.jsp/../ssoLogin.do");
            // TODO @jimmielin: who knows about #valid_code, #sms_code...???
        $sResult = curl_exec($cConn);

        if(curl_errno($cConn)) {
            if(!$inPKU && preg_match('/HTTP code 407/si', curl_error($cConn))) {
                $this->errorID = 1;
                return false;
            }

            $this->errorID = 9; // network error that we cannot resolve
            return false;
        }

        if(!$inPKU && preg_match('/407 Proxy Authentication Required/siu', $sResult)) {
            $this->errorID = 1; // user authentication failed, if you fail proxy its dead
            return false;
        }

        $jResults = json_decode($sResult);

        if(!$jResults->success) {
            if($jResults->errors->msg == "密码错误") {
                $this->errorID = 1; return false;
            }

            $this->errorID = 9;
            return false;
        }
        
        // okay! keep the token now. we should poll the portal at https://portal.pku.edu.cn/portal2013/account/getBasicInfo.do
        $token = $jResults->token;
        // notImplemented

        curl_close($cConn);
        $this->errorID = 0; // success
        return true;
    }

    /**
     * Return error code, if any.
     * @return        Int
     */
    public function error() { return $this->errorID; }
}