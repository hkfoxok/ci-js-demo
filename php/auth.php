<?php
#include 'conf.php'
namespace Tencentyun;

class Auth
{

    const AUTH_URL_FORMAT_ERROR = -1;
    const AUTH_SECRET_ID_KEY_ERROR = -2;
	
	
	const PKG_VERSION = '2.0.1'; 
    const API_IMAGE_END_POINT = 'http://web.image.myqcloud.com/photos/v1/';
    const API_IMAGE_END_POINT_V2 = 'http://web.image.myqcloud.com/photos/v2/';
	const API_VIDEO_END_POINT = 'http://web.video.myqcloud.com/videos/v1/';
	
	const API_PRONDETECT_URL = 'http://service.image.myqcloud.com/detection/pornDetect';    
		
    // 以下部分请您根据在qcloud申请到的项目id和对应的secret id和secret key进行修改
    const APPID = 10030012;
    const SECRET_ID = 'AKID1bvHeG324hT7wngYmi3CSfBLmnzt49Ze';
    const SECRET_KEY = '6GjtLYAYAZqiTirn78uT8dKvb9xYX6o2';

    /**
     * 支持自定义fileid签名函数
     * 复制、删除操作，fileid必须指定，且expired为0
     * @param  string $bucket  空间名称
     * @param  string $fileid  自定义fileid，无需urlencode
     * @param  int $expired    过期时间，单次签名请传0并指定fileid
     * @return userid          用户userid，建议不指定
     */
    public static function getAppSignV2($bucket, $fileid, $expired, $userid = '0') {

        $secretId = self::SECRET_ID;
        $secretKey = self::SECRET_KEY;
        $appid = self::APPID;
        
        if (empty($secretId) || empty($secretKey) || empty($appid)) {
            ImageV2::setMessageInfo(-1,"sign error");
            return false;
        }
        
        $puserid = '';
        if (isset($userid)) {
            if (strlen($userid) > 64) {
                ImageV2::setMessageInfo(-1,"sign error");
                return false;
            }
            $puserid = $userid;
        }
                    
        $now = time();    
        $rdm = rand();

        $plainText = 'a='.$appid.'&b='.$bucket.'&k='.$secretId.'&e='.$expired.'&t='.$now.'&r='.$rdm.'&u='.$puserid.'&f='.$fileid;
        $bin = hash_hmac("SHA1", $plainText, $secretKey, true);
        $bin = $bin.$plainText;        
        $sign = base64_encode($bin);        
        return $sign;
    }

    

    /**
     * 签名函数（上传、下载会生成多次有效签名，复制删除资源会生成单次有效签名）
	 * 如果需要针对下载生成单次有效签名，请使用函数appSign_once
     * @param  string $url     请求url
     * @param  int $expired    过期时间
     * @return string          签名
     * @deprecated deprecated since v2 
     */
    public static function appSign($url, $expired) {

        $secretId = self::SECRET_ID;
        $secretKey = self::SECRET_KEY;

        if (empty($secretId) || empty($secretKey)) {
            return self::AUTH_SECRET_ID_KEY_ERROR;
        }

        $urlInfo = self::getInfoFromUrl($url);
        if (empty($urlInfo)) {
            return self::AUTH_URL_FORMAT_ERROR;
        }

        $cate   = isset($urlInfo['cate']) ? $urlInfo['cate'] : '';
        $ver    = isset($urlInfo['ver']) ? $urlInfo['ver'] : '';
        $appid  = $urlInfo['appid'];
        $userid = $urlInfo['userid'];
        $oper   = isset($urlInfo['oper']) ? $urlInfo['oper'] : '';
        $fileid = isset($urlInfo['fileid']) ? $urlInfo['fileid'] : '';
        $style = isset($urlInfo['style']) ? $urlInfo['style'] : '';

        $onceOpers = array('del', 'copy');
        if ($fileid || ($oper && in_array($oper, $onceOpers))) {
            $expired = 0;
        }
        
        $puserid = '';
        if (!empty($userid)) {
            if (strlen($userid) > 64) {
                return self::AUTH_URL_FORMAT_ERROR;
            }
            $puserid = $userid;
        }
                    
        $now = time();    
        $rdm = rand();

        $plainText = 'a='.$appid.'&k='.$secretId.'&e='.$expired.'&t='.$now.'&r='.$rdm.'&u='.$puserid.'&f='.$fileid;
        $bin = hash_hmac("SHA1", $plainText, $secretKey, true);
        $bin = $bin.$plainText;        
        $sign = base64_encode($bin);        
        return $sign;
    }

	 /**
     * 生成单次有效签名函数（用于复制、删除和下载指定fileid资源，使用一次即失效）
     * @param  string $fileid     文件唯一标识符
	 * @param  string $userid  开发者账号体系下的userid，没有请使用默认值0
     * @return string          签名
     */
    public static function appSign_once($fileid, $userid = '0') {

        $secretId = Conf::SECRET_ID;
        $secretKey = Conf::SECRET_KEY;
		$appid = Conf::APPID;
		
        if (empty($secretId) || empty($secretKey) || empty($appid)) {
            return self::AUTH_SECRET_ID_KEY_ERROR;
        }
        
        $puserid = '';
        if (!empty($userid)) {
            if (strlen($userid) > 64) {
                return self::AUTH_URL_FORMAT_ERROR;
            }
            $puserid = $userid;
        }
                    
        $now = time();    
        $rdm = rand();

        $plainText = 'a='.$appid.'&k='.$secretId.'&e=0'.'&t='.$now.'&r='.$rdm.'&u='.$puserid.'&f='.$fileid;
        $bin = hash_hmac("SHA1", $plainText, $secretKey, true);
        $bin = $bin.$plainText;        
        $sign = base64_encode($bin);        
        return $sign;
    }
	
	/**
     * 生成多次有效签名函数（用于上传和下载资源，有效期内可重复对不同资源使用）
     * @param  int $expired    过期时间
	 * @param  string $userid  开发者账号体系下的userid，没有请使用默认值0
     * @return string          签名
     */
    public static function appSign_more($expired,$userid = '0') {

        $secretId = self::SECRET_ID;
        $secretKey = self::SECRET_KEY;
		$appid = self::APPID;
		
        if (empty($secretId) || empty($secretKey) || empty($appid)) {
            return self::AUTH_SECRET_ID_KEY_ERROR;
        }
        
        $puserid = '';
        if (!empty($userid)) {
            if (strlen($userid) > 64) {
                return self::AUTH_URL_FORMAT_ERROR;
            }
            $puserid = $userid;
        }
                    
        $now = time();    
        $rdm = rand();

        $plainText = 'a='.$appid.'&k='.$secretId.'&e='.$expired.'&t='.$now.'&r='.$rdm.'&u='.$puserid.'&f=';
        $bin = hash_hmac("SHA1", $plainText, $secretKey, true);
        $bin = $bin.$plainText;        
        $sign = base64_encode($bin);        
        return $sign;
    }
	
	public static function generateResUrl($bucket, $userid=0, $fileid='', $oper = '') {
        if ($fileid) {
            $fileid = urlencode($fileid);
            if ($oper) {
                return self::API_IMAGE_END_POINT_V2 . self::APPID . '/' . $bucket . '/' . $userid . '/' . $fileid . '/' . $oper;
            } else {
                return self::API_IMAGE_END_POINT_V2 . self::APPID . '/' . $bucket . '/' . $userid . '/' . $fileid;
            }
        } else {
            return self::API_IMAGE_END_POINT_V2 . self::APPID . '/' . $bucket . '/' . $userid;
        }
    }

    
    
}	
		$bucket = 'test2';
		$userid = 0;
		$fileid = 'sample'.time();                              // 自定义文件名
        //生成新的上传签名
        $url = Auth::generateResUrl($bucket, $userid, $fileid);
        $expired = time() + 999;
        $sign = Auth::getAppSignV2($bucket, $fileid, $expired);
        $ret = array('url' => $url,'sign' => $sign);
	
	
    
    echo json_encode($ret);

//end of script
