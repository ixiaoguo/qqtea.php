<?php

	/*
		通过 Email 反查绑定的 QQ 号码
	*/

	require(__DIR__ . '/QQTEA.php');

	function bin2show($bin){
		return wordwrap(trim(preg_replace('/(..)/', '$1 ', bin2hex($bin))), 0x40, "\n") . "\n";
	}


	$email = 'i@vimer.org'; //要查询的Email

	//加密数据包的KEY(随机生成 16 字节的内容), 此处使用固定的
	$key = hex2bin('923FE07016166ED30B1DE7FC12BF1C4A');


	//构造请求指令
	$body = sprintf('%02X%02X%s', 2, strlen($email), bin2hex($email));

	//使用KEY对其进行加密
	$body = QQTEA::encrypt($key, hex2bin($body));

	$msg = "\x02".			//包头
	"\x12\x21".				//协议版本
	"\x00\xB2".				//包指令
	"\x0D\x1B".				//包序列(随机数字)
	"\x00\x00\x00\x00" .	//固定
	$key .					//加密key
	$body .					//加密后的包体
	"\x03";					//包尾


	echo "Send: \n", bin2show($msg);

	$len = strlen($msg);

	/*
	腾讯QQ的UDP服务器地址
	可用列表:
		sz.tencent.com
		sz2.tencent.com
		sz3.tencent.com
		sz4.tencent.com
		sz5.tencent.com
		sz6.tencent.com
		sz7.tencent.com
		sz8.tencent.com
		sz9.tencent.com
	*/
	$ip = 'sz2.tencent.com';
	$port = 8000;

	$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

	//如果这里发送超时, 可尝试更换上面的 $ip 为服务器列表中的另一个
	socket_sendto($sock, $msg, $len, 0, $ip, $port);

	socket_recvfrom($sock, $buf, 0xfff, 0, $ip, $port);

	socket_close($sock);

	//输出收到的数据包
	echo "Receive: \n", bin2show($buf);

	//得到包体
	$body = substr($buf, 7, -1);

	//解密
	$body = QQTEA::decrypt($key, $body);

	echo "Decrypt: \n", bin2show($body);

	//提取 QQ 号码
	$qq = substr($body, 2, 4);

	echo "QQ Hex: ", bin2show($qq);

	//unpack string with unsigned long (always 32 bit, big endian byte order)
	$qq = unpack('N*', $qq);

	echo "QQ:     ", $qq[1];

