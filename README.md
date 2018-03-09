# suave-letsencrypt

A small package that integrates [certes](https://github.com/fszlin/certes/) with [suave](https://suave.io).

## Installation

Currently you need to clone this repository and build the Suave.LetsEncrypt project yourself. Then you can reference it in your own Suave project.

See the Suave.LetsEncrypt.Demo project on how to use it.
Essentially you use CertAutoUpdate.startWebServer instead of Suave's startWebServer and provide a method which takes the provided certificate to setup you https bindings.
