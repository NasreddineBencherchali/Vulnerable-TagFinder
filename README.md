# XSS-Finder [![python](https://img.shields.io/badge/Python-2.7-green.svg?style=style=flat-square)](https://www.python.org/downloads/)  [![version](https://img.shields.io/badge/Version-Beta-blue.svg?style=style=flat-square)](https://twitter.com/nas_bench)

## Description

When handling data sometimes programmers needs to render it as it came from it's orignal source. And somtimes this data is controlled by the user, which may lead to a Cross Site Scripting (XSS) attack.

The following is a python script that searches for these **user controlled** / **"vulnerable"** tags (Renders HTML).

Currently support:

* JSF
* PrimeFaces

## Usage

```bash
python XSS-Finder.py -h
```
