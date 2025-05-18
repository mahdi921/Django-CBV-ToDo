{% extends "mail_templated/base.tpl" %}

{% block subject %}
Account Activation
{% endblock %}

{% block html %}
To activate your account, please click the link below:
<br><br>
<a href="http://localhost:8000/accounts/api/v1/activation/confirm/{{token}}">Activate</a>
<br><br>
If you did not request this email, please ignore it. Your account will remain unchanged.
<br><br>
Thank you for using our service!
<br><br>
Best regards,
<br>
The Backend Team
{% endblock %}