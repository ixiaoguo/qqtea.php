<?php


require_once(__DIR__ . '/QQTEA.php');

/*
以下为测试代码:
*/

function bin2show($bin){
	return wordwrap(trim(preg_replace('/(..)/', '$1 ', bin2hex($bin))), 0x40, "\n") . "\n";
}


$key = 'thisiskey';
$data = "Hello World!(你好 世界!)" . microtime() . "" . rand(123456, 34567890);

echo "Data: \n", $data, "\n";

//qqtea 加密
$r = QQTEA::encrypt($key, $data);

echo "Encrypt: \n", bin2show($r);

//qqtea 解密
$b = QQTEA::decrypt($key, $r);

echo "Decrypt: \n", bin2show($b);

echo "Binary String: \n", $b, "\n";

var_dump($b === $data);
