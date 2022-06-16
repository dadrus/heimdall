---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
draft: false
menu:
  main:
    identifier: "{{ lower (replace .Name "-" "")  }}"
    weight: 100
    parent: ""
---

# {{ .Name }}
