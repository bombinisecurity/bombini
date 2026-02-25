# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [proto/config.proto](#proto_config-proto)
    - [FileMonConfig](#config-FileMonConfig)
    - [GTFOBinsConfig](#config-GTFOBinsConfig)
    - [HookConfig](#config-HookConfig)
    - [NetMonConfig](#config-NetMonConfig)
    - [ProcMonConfig](#config-ProcMonConfig)
    - [Rule](#config-Rule)
  
- [Scalar Value Types](#scalar-value-types)



<a name="proto_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## proto/config.proto



<a name="config-FileMonConfig"></a>

### FileMonConfig
Configuration file for FileMon detector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| file_open | [HookConfig](#config-HookConfig) |  | security_file_open config. |
| path_truncate | [HookConfig](#config-HookConfig) |  | security_path_truncate config. |
| path_unlink | [HookConfig](#config-HookConfig) |  | security_path_unlink config. |
| path_symlink | [HookConfig](#config-HookConfig) |  | security_path_symlink config. |
| path_chmod | [HookConfig](#config-HookConfig) |  | security_path_chmod config. |
| path_chown | [HookConfig](#config-HookConfig) |  | security_path_chown config. |
| sb_mount | [HookConfig](#config-HookConfig) |  | security_sb_mount config. |
| mmap_file | [HookConfig](#config-HookConfig) |  | security_mmap_file config. |
| file_ioctl | [HookConfig](#config-HookConfig) |  | security_file_ioctl config. |






<a name="config-GTFOBinsConfig"></a>

### GTFOBinsConfig
Configuration file for GTFOBinsDetector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enforce | [bool](#bool) |  | Block execution of GTFOBins binaries. |
| gtfobins | [string](#string) | repeated | GTFOBins executables names. |






<a name="config-HookConfig"></a>

### HookConfig
Hook or group of hooks configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enabled | [bool](#bool) |  | Load eBPF programs |
| rules | [Rule](#config-Rule) | repeated | Filtering rules |






<a name="config-NetMonConfig"></a>

### NetMonConfig
Configuration file for NetMon detector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ingress | [HookConfig](#config-HookConfig) |  | Ingress traffic connections |
| egress | [HookConfig](#config-HookConfig) |  | Egress traffic connections |






<a name="config-ProcMonConfig"></a>

### ProcMonConfig
Configuration file for ProcMon detector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| setuid | [HookConfig](#config-HookConfig) |  | setuid hook config. |
| capset | [HookConfig](#config-HookConfig) |  | capset hook config. |
| prctl | [HookConfig](#config-HookConfig) |  | prctl hook config. |
| create_user_ns | [HookConfig](#config-HookConfig) |  | create_user_ns hook config. |
| ptrace_access_check | [HookConfig](#config-HookConfig) |  | ptrace_attach hook config. |
| setgid | [HookConfig](#config-HookConfig) |  | setgid hook config. |
| ima_hash | [bool](#bool) | optional | Collect IMA hashes for executed binaries. |
| gc_period | [uint64](#uint64) | optional | GC period for PROCMON_PROC_MAP default 30 sec. |






<a name="config-Rule"></a>

### Rule
Rule definition. Scope and event predicates are used as logical conjunction.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name of the rule. |
| scope | [string](#string) |  | Logical predicate describes scope this rule will be applied, e.g. process, container. |
| event | [string](#string) |  | Logical predicate for describes event rule will be applied |





 

 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

