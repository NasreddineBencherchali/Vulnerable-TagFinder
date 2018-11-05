# XSS-Finder  [![python](https://img.shields.io/badge/Python-3-green.svg?style=style=flat-square)](https://www.python.org/downloads/)  [![version](https://img.shields.io/badge/Version-Beta-blue.svg?style=style=flat-square)](https://twitter.com/nas_bench)

## Description

When processing data, programmers sometimes need to render it as it came from it's orignal source. And sometimes this data is or can be controlled by the user, which can lead to a Cross Site Scripting (XSS) attack.

This is a python script that searches for these **User Controlled** / **"Vulnerable"** tags (Renders HTML).

Currently support the tags for the following libraries :

* JSF
* PrimeFaces

## Usage

```bash
python XSS-Finder.py -h
```
