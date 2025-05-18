{% extends "mail_templated/base.tpl" %}

{% block subject %}
TEST
{% endblock %}

{% block html %}
test email
hi {{name}}
{% endblock %}