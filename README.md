# Introduction

This python modules enables compiling iptable rulesets from a custom yaml format, introducing loops and scope-enabled variables. It is possible to import other yaml files. See `examples/`.

# Dependencies

* python 3.6
* python yaml

# Use

```sh
python yiptables.py examples/example.yml
```