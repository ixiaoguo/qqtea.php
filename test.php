<?php


require_once(__DIR__ . '/QQTEA.php');

/*
以下为测试代码:
*/

function output($str){
	var_dump(trim(preg_replace('/(..)/', '$1 ', bin2hex($str))));
}

$key = 'thisiskey';
$data = "Hello World!(你好 世界!)" . microtime() . "" . rand(123456, 34567890);

echo "Data: $data\n";

//qqtea 加密
$r = QQTEA::encrypt($key, $data);

output($r);

//qqtea 解密
$b = QQTEA::decrypt($key, $r);

output($b);

echo $b, "\n";

var_dump($b === $data);
