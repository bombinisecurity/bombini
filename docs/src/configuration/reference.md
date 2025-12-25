# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [proto/config.proto](#proto_config-proto)
    - [CapFilter](#config-CapFilter)
    - [ConnectionsControl](#config-ConnectionsControl)
    - [CredFilter](#config-CredFilter)
    - [FileHookConfig](#config-FileHookConfig)
    - [FileMonConfig](#config-FileMonConfig)
    - [GTFOBinsConfig](#config-GTFOBinsConfig)
    - [GidFilter](#config-GidFilter)
    - [IOUringMonConfig](#config-IOUringMonConfig)
    - [IpFilter](#config-IpFilter)
    - [NetMonConfig](#config-NetMonConfig)
    - [PathFilter](#config-PathFilter)
    - [ProcHookConfig](#config-ProcHookConfig)
    - [ProcMonConfig](#config-ProcMonConfig)
    - [ProcessFilter](#config-ProcessFilter)
    - [UidFilter](#config-UidFilter)
  
- [Scalar Value Types](#scalar-value-types)



<a name="proto_config-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## proto/config.proto



<a name="config-CapFilter"></a>

### CapFilter
Capabilities filter


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| effective | [string](#string) | repeated | List of effective Capabilities. Special name ANY means if any cap is in effective cap set. |
| deny_list | [bool](#bool) | optional | if true acts like deny list |






<a name="config-ConnectionsControl"></a>

### ConnectionsControl
Connections control


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enabled | [bool](#bool) |  | Load eBPF programs |
| ipv4_filter | [IpFilter](#config-IpFilter) |  | Ipv4 filter connections |
| ipv6_filter | [IpFilter](#config-IpFilter) |  | Ipv6 filter connections |






<a name="config-CredFilter"></a>

### CredFilter
Filter Events using Cred information. Pattern uid_filter || cap_filter.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid_filter | [UidFilter](#config-UidFilter) |  | Filter by uids (euid, TODO: uid, fsuid). |
| cap_filter | [CapFilter](#config-CapFilter) |  | Filter by caps (effective, TODO: permitted, inheritable). |
| gid_filter | [GidFilter](#config-GidFilter) |  | Filter by gids (euid, TODO: gid, fsgid). |






<a name="config-FileHookConfig"></a>

### FileHookConfig
FileMon hook configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enabled | [bool](#bool) |  | Load eBPF programs |
| path_filter | [PathFilter](#config-PathFilter) | optional | Filter event by Path |






<a name="config-FileMonConfig"></a>

### FileMonConfig
Configuration file for FileMon detector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| file_open | [FileHookConfig](#config-FileHookConfig) |  | security_file_open config. |
| path_truncate | [FileHookConfig](#config-FileHookConfig) |  | security_path_truncate config. |
| path_unlink | [FileHookConfig](#config-FileHookConfig) |  | security_path_unlink config. |
| path_chmod | [FileHookConfig](#config-FileHookConfig) |  | security_path_chmod config. |
| path_chown | [FileHookConfig](#config-FileHookConfig) |  | security_path_chown config. |
| sb_mount | [FileHookConfig](#config-FileHookConfig) |  | security_sb_mount config. |
| mmap_file | [FileHookConfig](#config-FileHookConfig) |  | security_mmap_file config. |
| file_ioctl | [FileHookConfig](#config-FileHookConfig) |  | security_file_ioctl config. |
| process_filter | [ProcessFilter](#config-ProcessFilter) |  | Filter File events by Process information. |






<a name="config-GTFOBinsConfig"></a>

### GTFOBinsConfig
Configuration file for GTFOBinsDetector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enforce | [bool](#bool) |  | Block execution of GTFOBins binaries. |
| gtfobins | [string](#string) | repeated | GTFOBins executables names. |






<a name="config-GidFilter"></a>

### GidFilter
GID filter


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| egid | [uint32](#uint32) | repeated | effective GID |






<a name="config-IOUringMonConfig"></a>

### IOUringMonConfig
Configuration file for IOUringMon detector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process_filter | [ProcessFilter](#config-ProcessFilter) |  | Filter io_uring events by Process information. |






<a name="config-IpFilter"></a>

### IpFilter
IP filter configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| src_ip | [string](#string) | repeated | Source IP list |
| dst_ip | [string](#string) | repeated | Destination IP list |
| deny_list | [bool](#bool) |  | deny_list |






<a name="config-NetMonConfig"></a>

### NetMonConfig
Configuration file for NetMon detector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process_filter | [ProcessFilter](#config-ProcessFilter) |  | Filter Network events by Process information. |
| ingress | [ConnectionsControl](#config-ConnectionsControl) |  | Ingress traffic connections |
| egress | [ConnectionsControl](#config-ConnectionsControl) |  | Egress traffic connections |






<a name="config-PathFilter"></a>

### PathFilter
Path filtering args


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | repeated | List of executables names to filter. |
| path | [string](#string) | repeated | List of full executable paths to filter. |
| prefix | [string](#string) | repeated | List of executable path prefixes to filter. |






<a name="config-ProcHookConfig"></a>

### ProcHookConfig
ProcMon hook configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enabled | [bool](#bool) |  | Load eBPF programs |
| cred_filter | [CredFilter](#config-CredFilter) |  | Filter by Cred |






<a name="config-ProcMonConfig"></a>

### ProcMonConfig
Configuration file for ProcMon detector


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| setuid | [ProcHookConfig](#config-ProcHookConfig) |  | setuid hook config. |
| capset | [ProcHookConfig](#config-ProcHookConfig) |  | capset hook config. |
| prctl | [ProcHookConfig](#config-ProcHookConfig) |  | prctl hook config. |
| create_user_ns | [ProcHookConfig](#config-ProcHookConfig) |  | create_user_ns hook config. |
| ptrace_access_check | [ProcHookConfig](#config-ProcHookConfig) |  | ptrace_attach hook config. |
| setgid | [ProcHookConfig](#config-ProcHookConfig) |  | setgid hook config. |
| process_filter | [ProcessFilter](#config-ProcessFilter) |  | Process Filter Configuration. |
| ima_hash | [bool](#bool) | optional | Collect IMA hashes for executed binaries. |
| gc_period | [uint64](#uint64) | optional | GC period for PROCMON_PROC_MAP default 30 sec. |






<a name="config-ProcessFilter"></a>

### ProcessFilter
Filter Events using process information.
Filtering is based on pattern: uid AND euid AND auid AND (binary.name OR binary.prefix OR binary.path).
All variables in the pattern are optional. if deny_list is true filter acts as a deny list, otherwise it
is an allow list.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [uint32](#uint32) | repeated | List of UID&#39;s to filter. |
| euid | [uint32](#uint32) | repeated | List of EUID&#39;s to filter. |
| auid | [uint32](#uint32) | repeated | List of AUID&#39;s (login uid) to filter. |
| binary | [PathFilter](#config-PathFilter) |  | Binary filter args |
| deny_list | [bool](#bool) |  | if true acts like deny list |






<a name="config-UidFilter"></a>

### UidFilter
UID filter


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| euid | [uint32](#uint32) | repeated | effective UID |





 

 

 

 



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

