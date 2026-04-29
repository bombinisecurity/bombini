# Rules

Bombini agent implements a powerful event filtering mechanism that operates entirely within the eBPF layer. This approach
ensures minimal overhead and maximum performance by filtering events at the kernel level before they reach user space.

## Configuration Structure

Rules are defined in YAML format and organized by hook or hook group. The basic structure follows this pattern:

```yaml
<hook_name>:
  enabled: <boolean>
  rules:
    - rule: <rule_name>
      scope: <boolean_predicate>
      event: <boolean_predicate>
```

**Example Configuration**

```yaml
file_open:
  enabled: true
  rules:
    - rule: monitor_sensitive_files
      scope: binary_path in ["/usr/bin/cat", "/usr/bin/tail"]
      event: path_prefix == "/etc" AND name in ["passwd", "shadow", "sudoers"]
```

### Rule Components

**Scope Predicate.**
The scope predicate defines the subject to which the rule applies. This typically describes executable or host.
To capture all events corresponding to the entire host, just keep scope predicate empty (or remove it from the rule). Executable context can be configured using the following attribute maps:

* **binary_path**: Full absolute path to executable
* **binary_name**: Executable name
* **binary_prefix**: Absolute path prefix for the executable (up to 255 bytes)


**Event Predicate.**
The event predicate defines the event characteristics that should trigger the rule. Attribute maps for event filtering
are specific for hook associated with the rule. Attribute description can be found in detectors configuration chapters.

**Predicate Combination.**
The scope and event predicates are combined using logical *AND*. This means both conditions must be satisfied for the rule. It's is possible to use only scope or event predicate. For this purpose just remove it from rule.


### Boolean Predicate Syntax

| Operation   | Syntax      | Description                                      | Example                                      |
|-------------|-------------|--------------------------------------------------|----------------------------------------------|
| AND         | `AND`       | Logical conjunction                              | `path_prefix == "/etc" AND name == "passwd"` |
| OR          | `OR`        | Logical disjunction                              | `binary_path == "/usr/bin/cat" OR binary_path == "/usr/bin/tail"` |
| NOT         | `NOT`       | Logical negation                                 | `NOT uid in [2000, 1000]` |
| Grouping    | `( )`       | Control evaluation precedence                    | `(A OR B) AND C`                             |
| Membership  | `in`        | Check value existence in list                    | `name in ["passwd", "shadow", "sudoers"]` |
| Equality    | `==`        | Shorthand for single-element membership check    | `binary_path == "/usr/bin/cat"`              |


**Operator Precedence**

The following precedence order applies (from highest to lowest):

1. Parentheses *()*, *in*, *==*
2. *NOT*
3. *AND*
4. *OR*

**In Operator**

The `in` operator is used to check if a value exists in a list. It can be used with both string and integer lists.
Integers can be specified in decimal or hexadecimal format. There is a difference how strings are handled. For example,
for `path` attribute map strings are considered as path strings. For ipv4/ivp6 address strings are considered as CIDRs,
for example: `"2000::/3"` is a CIDR for IPv6. And last but not least, some attribute maps consider strings as bit flags,
for example, for `ecaps` attribute map, `["CAP_SYS_ADMIN", "CAP_SYS_PTRACE"]` will check if any of this flags (capabilities) are set.


## Technical Limitations

1. Maximum rules per hook: 32
2. Maximum operations per rule: 16
3. Maximum in operations per attribute in rule: 8

The last two constraints are applied to optimized rule.

## Rule Optimizations

Bombini agent applies several optimizations to rules to improve performance:

* fold_not
* fold_or
* fold_and

### Fold_or Optimization

The `fold_or` optimization combines multiple OR operations with underling "in" containing the same attribute map into a single "in" operation.

**Example**

```yaml
file_open:
  enabled: true
  rules:
    - rule: monitor_sensitive_files
      event: path == "/etc" OR path == "/var" OR path in ["/etc", "/tmp", "/opt"]
```

This rule will be optimized to:

```yaml
file_open:
  enabled: true
  rules:
    - rule: monitor_sensitive_files
      event: path in ["/etc", "/tmp", "/opt", "/var"]
```

### Fold_and Optimization

The `fold_and` optimization combines multiple AND operations with underling "in" containing the same attribute map into a single "in" operation.

**Example**

```yaml
file_open:
  enabled: true
  rules:
    - rule: monitor_sensitive_files
      event: path == "/etc" AND path in ["/etc", "/tmp", "/opt"]
```

This rule will be optimized to:

```yaml
file_open:
  enabled: true
  rules:
    - rule: monitor_sensitive_files
      event: path in ["/etc"]
```

Also, this optimization checks if predicate is always false, and returns error:

```yaml
file_open:
  enabled: true
  rules:
    - rule: monitor_sensitive_files
      event: path == "/log" AND path in ["/etc", "/tmp", "/opt"]
```

### Fold_not Optimization

The `fold_not` optimization combines multiple NOT operations into a single NOT operation using De Morgan's laws.

**Example**

```yaml
file_open:
  enabled: true
  rules:
    - rule: fold_not_and
      event: NOT path == "/var" AND NOT path == "/tmp"
```

This rule firstly will be optimized to:

```yaml
file_open:
  enabled: true
  rules:
    - rule: fold_not_and
      event: NOT (path == "/var" OR path == "/tmp")
```

And resulting rule after `fold_or` optimization will be:

```yaml
file_open:
  enabled: true
  rules:
    - rule: fold_not_and
      event: NOT path in ["/var", "/tmp"]
```

## Sandbox Mode

Bombini supports sandboxing for ProcMon and FileMon detectors, allowing to define fine-grained access control policies that are enforced directly in-kernel via eBPF LSM hooks. When enabled, sandboxing evaluates rules in enforcement mode: matching events can be allowed or denied based on the configured policy. In allow-list mode, `event` restrictions are tied to the `scope` of the event. If there is no `scope` restriction, the `event` restriction is applied to the entire host.

Sandbox configuration is added at the hook level and follows this pattern:

```yaml
<hook_name>:
  enabled: <boolean>
  sandbox:
    enabled: <boolean> # optional, default: false
    deny_list: <boolean>  # optional, default: false
  rules:
    - rule: <rule_name>
      scope: <boolean_predicate>
      event: <boolean_predicate>
```

### Sandbox Parameters

* **enabled**: Activates sandbox enforcement for the hook. When false, rules operate in monitoring-only mode.
* **deny_list**: Controls policy mode:
  - false (default): *Allow-list mode* — only events matching rules are permitted; all others are denied.
  - true: *Deny-list mode* — events matching rules are explicitly blocked; all others are permitted.

### Examples

Prevent `dash`, `sh` and `bash` from writing to `filemon.yaml`:

```yaml
file_open:
  enabled: true
  sandbox:
    enabled: true
    deny_list: true
  rules:
  - rule: OpenTestSandBoxRule
    scope: binary_name in ["dash", "sh", "bash"]
    event: name == "filemon.yaml" AND access_mode == "O_WRONLY"
```

Allow `head` command to read only files from `/usr/lib` or read `filemon.yaml`:

```yaml
file_open:
  enabled: true
  sandbox:
    enabled: true
  rules:
  - rule: OpenTestSandBoxRule
    scope: binary_name == "head"
    event: path_prefix == "/usr/lib" OR name in ["filemon.yaml"]
```

Only binaries from the specified paths can be executed:

```yaml
bprm_check:
  enabled: true
  sandbox:
    enabled: true
  rules:
  - rule: BprmCheckTestRule
    event: path_prefix in ["/usr", "/bin", "/sbin", "/home"]
```
