## 原理
文章: [[原创] Qt6 MetaObject解析脚本](https://bbs.kanxue.com/thread-290839.htm)  

## 使用方式
将该项目放入ida插件目录下即可:  
- Windows: %APPDATA%\Hex-Rays\IDA Pro\plugins
- macOS: ~/.idapro/plugins or ~/Library/Application Support/IDA Pro/plugins
- Linux: ~/.idapro/plugins 

遇到MetaObject数据结构(或者主动去找QMetaObject::activate/QObject::connectImpl的参数, 就是这个数据结构), 按 `Alt+;` 即可.  
