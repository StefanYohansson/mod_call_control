mod-call-control
====

The idea behind call control is to have a way to control a call without a socket.
The module exposes the internal APIs via REST API and send events and async answers via webhook to a configured webhook.


## Building

```shell
git submodule update --init
make build-deps
make
make install
```
