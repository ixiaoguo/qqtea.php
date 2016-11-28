<?php

class QQTEA {
	const PADDING = "\x00\x00\x00\x00\x00\x00\x00";
	const DELTA = 0x9E3779B9;
	const ROUND = 0x10;//16轮加密

	private static function stringToLongArray($s) {
		return array_values(unpack('N*', str_repeat("\0", (4 - strlen($s) % 4) & 3) . $s));
	}

	private static function longArrayToString($data) {
		array_unshift($data, 'N*');
		return call_user_func_array('pack', $data);
	}

	private static function X_O_R($a, $b){
		$c = self::stringToLongArray($a);
		$d = self::stringToLongArray($b);

		$n = count($c);

		for($i=0; $i<$n; $i++){
			$c[$i] ^= $d[$i];
		}

		return self::longArrayToString($c);
	}

	private static function encipher($v, $key){
		$sum = self::DELTA;
		$n = self::ROUND;

		$data = self::stringToLongArray($v);

		while($n-- > 0){
			$data[0] += (($data[1] << 4) + $key[0]) ^ ($data[1] + $sum) ^ (($data[1] >> 5) & 0x7ffffff) + $key[1];
			$data[1] += (($data[0] << 4) + $key[2]) ^ ($data[0] + $sum) ^ (($data[0] >> 5) & 0x7ffffff) + $key[3];

			$sum += self::DELTA;
		}

		return self::longArrayToString($data);
	}

	private static function decipher($v, $key){
		$sum = self::DELTA << 4;
		$n = self::ROUND;

		$data = self::stringToLongArray($v);

		while($n-- > 0){
			$data[1] -= ((($data[0] << 4) & 0xFFFFFFF0) + $key[2]) ^ ($data[0] + $sum) ^ (($data[0] >> 5) & 0x07ffffff) + $key[3];

			$data[0] -= ((($data[1] << 4) & 0xFFFFFFF0) + $key[0]) ^ ($data[1] + $sum) ^ (($data[1] >> 5) & 0x07ffffff) + $key[1];

			$sum -= self::DELTA;
		}

		return self::longArrayToString($data);
	}

	private static function fixKey($k){
		//QQTEA 的加/解密key的长度要求必须为 16位, 所以当长度不够时, 自动在前面补0
		if(strlen($k) !== 0x10){
			$k = str_repeat("\x00", 0x10) . $k;
			$k = substr($k, strlen($k) - 0x10);
		}

		return $k;
	}


	public static function encrypt($k, $v){
		$k = self::stringToLongArray(self::fixKey($k));

		$vl = strlen($v);

		$FILL_N_OR = 0xF8;

		//计算需要填充的字节数
		$filln = (8 - ($vl + 2)) % 8;
		$filln += 2 + ($filln < 0 ? 8 : 0);

		//填充随机数据, 以达到每次加密后的数据都不一样的目的
		$prefix = '';
		for($i=0; $i<$filln; $i++){
			$prefix .= chr(rand(1, 0xfe));
		}

		$v = sprintf("%s%s%s%s",
			chr(($filln - 2) | $FILL_N_OR),	//(填充的长度 - 2) | FILL_N_OR
			$prefix,	//填充的字符
			$v,		//原数据
			self::PADDING	//尾部填充的 7 字节的 \0, 用于在解密的时候, 确认数据解密成功
		);

		$tr = str_repeat("\x00", 8);
		$to = $tr;
		$r = '';

		$vl = strlen($v);

		for($i=0; $i<$vl ; $i += 8){
			$o = self::X_O_R(substr($v, $i, 8), $tr);
			$tr = self::X_O_R(self::encipher($o, $k), $to);
			$to = $o;
			$r .= $tr;
		}

		return $r;
	}

	public static function decrypt($k, $v){
		$k = self::stringToLongArray(self::fixKey($k));

		$l = strlen($v);
		$preCrypt = substr($v, 0, 8);

		$prePlain = self::decipher($preCrypt, $k);

		$pos = (ord($prePlain[0]) & 0x7) + 2;

		$r = $prePlain;
		$i = 8;

		for(; $i < $l; $i += 8){
			$x = self::X_O_R(self::decipher(self::X_O_R(substr($v, $i, 8), $prePlain), $k), $preCrypt);
			$prePlain = self::X_O_R($x, $preCrypt);
			$preCrypt = substr($v, $i, 8);
			$r .= $x;
		}

		//检测尾部是否有 填充 7个字节的 0, 如果没有, 则认为解密失败
		if(substr($r, strlen($r) - 7) !== self::PADDING){
			return '';
		}

		$pos++;

		return substr($r, $pos, (strlen($r) - 7 - $pos));
	}
}
