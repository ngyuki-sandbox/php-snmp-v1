<?php
// SNMP Request v1 の実装
// http://www.geocities.co.jp/SiliconValley-SanJose/3377/

// php-snmp-v1 <ipaddr> <community> <oid>
main($argv);

function main($argv)
{
    $host = $argv[1];
    $comm = $argv[2];
    $oid  = $argv[3]; // .1.3.6.1.2.1.1.1.0

    $snmpRequest = new SnmpRequest();
    $ret = $snmpRequest->request($host, $comm, $oid);
    print_r($ret);
}

class SnmpRequest
{
    private static function enc($tag, $val)
    {
        $len = strlen($val);
        if ($len <= 0x7f) {
            return pack("CC", $tag, $len) . $val;
        } else if($len <= 0xff) {
            return pack("CCC", $tag, 0x80 | 1, $len) . $val;
        } else if($len <= 0xffff) {
            return pack("CCn", $tag, 0x80 | 2, $len) . $val;
        } else if($len <= 0xffffffff) {
            return pack("CCN", $tag, 0x80 | 4, $len) . $val;
        } else {
            throw new RuntimeException("Unable encode ... val too long ($len)");
        }
    }

    private static function enc_a($tag)
    {
        $args = func_get_args();
        $tag = array_shift($args);
        $val = implode('', $args);
        return self::enc($tag, $val);
    }

    private static function enc_int8($val)
    {
        return self::enc(0x02, pack("C", $val));
    }

    private static function enc_str($val)
    {
        return self::enc(0x04, $val);
    }

    private static function enc_null()
    {
        return self::enc(0x05, '');
    }

    private static function enc_oid($val)
    {
        return self::enc(0x06, self::oid2bin($val));
    }

    private static function oid2bin($val)
    {
        $val = trim($val, '.');
        $oids = explode('.', $val);

        $bin = chr((int)array_shift($oids) * 40 + (int)array_shift($oids));

        foreach ($oids as $id) {
            $tmp = array();
            $tmp[] = $id & 0x7f;
            $id = $id >> 7;
            while ($id > 0) {
                $tmp[] = $id & 0x7f | 0x80;
                $id = $id >> 7;
            }
            $tmp = array_reverse($tmp);
            foreach ($tmp as $v) {
                $bin .= chr($v);
            }
        }

        return $bin;
    }

    private static function bin2oid($bin)
    {
        $oids = array(null);
        $list = unpack("C*", $bin);
        $val = array_shift($list);
        $oids[] = (int)($val / 40);
        $oids[] = (int)($val % 40);

        $num = 0;

        foreach ($list as $val) {
            $num = ($val & 0x7f) | $num << 7;
            if (($val & 0x80) === 0) {
                $oids[] = $val | $num;
                $num = 0;
            }
        }

        return implode('.', $oids);
    }

    private static function bin2hex($bin)
    {
        $a = unpack("C*", $bin);

        $str = "";

        foreach ($a as $v) {
            $str .= sprintf("%02x ", $v);
        }

        return $str;
    }

    private static function make_request($community, $oid, $rid)
    {
        $packet = self::enc_a(0x30,

            // バージョン
            self::enc_int8(0),

            // コミュニティ,
            self::enc_str($community),

            // SNMPコマンド(GetRequest)
            self::enc_a(0xA0,

                // リクエストID
                self::enc_int8($rid),

                // エラーステータス
                self::enc_int8(0),

                // エラーインデックス
                self::enc_int8(0),

                // 要求するMIDデータ
                self::enc_a(0x30,

                    // MIDデータを入れるための入れ子構造のレコード
                    self::enc_a(0x30,
                        // MIB値を入れるためのレコード
                        self::enc_oid($oid),
                        self::enc_null()
                    )
                )
            )
        );

        return $packet;
    }

    public function request($host, $community, $oid)
    {
        $packet = self::make_request($community, $oid, 4);

        $socket = socket_create(AF_INET, SOCK_DGRAM,  SOL_UDP);
        socket_sendto($socket, $packet, strlen($packet), 0, $host, 161);

        $read = array($socket);
        $null = null;

        $select = socket_select($read, $null, $null, 30, 0);
        if ($select === false) {
            throw new RuntimeException(socket_strerror(socket_last_error()));
        }

        if (count($read) == 0) {
            throw new RuntimeException("Timeout");
        }

        socket_recv($socket, $data, 65535, 0);
        socket_close($socket);

        return self::parse_packet($data);
    }

    private static function parse_packet($packet)
    {
        return self::parse_ref($packet);
    }

    private static function parse_ref(&$packet)
    {
        $tag = self::parse_tag($packet);
        $len = self::parse_len($packet);

        $val = substr($packet, 0, $len);
        $packet = substr($packet, $len);

        $obj = new stdClass();

        $obj->tag = $tag;
        $obj->len = $len;
        $obj->val = self::parse_val($tag, $val);

        return $obj;
    }

    private static function parse_tag(&$packet)
    {
        // 仕様上 1byte とは限らないらしいが、1byte より大きくなることは無いらしい
        // 8bit目が 1 のタグ番号はタグ番号に余り意味が無い？
        // 7bit目は無視するのが無難？
        // コマンド系は "1010 xxxx" になるっぽい

        $tag = ord($packet[0]);
        $packet = substr($packet, 1);

        return $tag;
    }

    private static function parse_len(&$packet)
    {
        $len = ord($packet[0]);
        $packet = substr($packet, 1);

        if ($len & 0x80) {
            $len = $len & ~0x80;

            $buf = substr($packet, 0, $len);
            $packet = substr($packet, $len);

            $buf = unpack("C*", $buf);

            $len = 0;

            foreach ($buf as $v) {
                $len = $v | $len << 8;
            }
        }

        return $len;
    }

    private static function parse_val($tag, $val)
    {
        switch ($tag) {
            case 0x30: // Combination
            case 0xa0: // GetRequest
            case 0xa1: // GetNextRequest
            case 0xa2: // GetResponse
            case 0xa3: // SetRequest
            case 0xa4: // Trap
                $arr = array();
                while (strlen($val) > 0) {
                    $arr[] = self::parse_ref($val);
                }
                return $arr;

            case 0x02:
                /*
                $a = unpack("C*", $val);
                $a = array_reverse($a);
                $val = '';
                foreach ($a as $s) {
                    $val = sprintf("%02x", $s);
                }
                */
                return self::bin2hex($val);

            case 0x04:
                return $val;

            case 0x06:
                return self::bin2oid($val);

            default:
                return $val;
        }
    }
}
