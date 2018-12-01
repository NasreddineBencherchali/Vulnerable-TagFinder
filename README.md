# Vulnerable-TagFinder  [![python](https://img.shields.io/badge/Python-3-green.svg?style=style=flat-square)](https://www.python.org/downloads/)  [![version](https://img.shields.io/badge/Version-Beta-blue.svg?style=style=flat-square)](https://twitter.com/nas_bench)

## Description

Vulnerable-TagFinder parses every web page (xhtml, jsp) in your project, in search for :

* Known vulnerable tags for XSS attacks.
* "data exporter" tag for possible CSV injection.
* Tags that have the "transient" attribute set to "true" for possible CSRF attacks.
* Tags that have the "escape" attribute set to "false" for possible XSS attacks.

Currently support tags for the following libraries :

* JSF
* PrimeFaces

## Usage

```bash
python Vulnerable-TagFinder.py -h
```
