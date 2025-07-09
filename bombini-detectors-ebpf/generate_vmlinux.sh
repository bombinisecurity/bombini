#!/bin/bash

# Add you types to the generate command
aya-tool generate task_struct > "$(dirname "$0")"/src/vmlinux.rs
