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
3. Maximum in operations per rule: 8

The last two constraints are applied to optimized rule.

## Rule Optimizations

Bombini agent applies several optimizations to rules to improve performance:

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