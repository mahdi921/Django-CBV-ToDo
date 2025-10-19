from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"

    def ready(self):
        # this will import signal from accounts.signals
        # to do profile creation after user creation
        # or after user update
        import accounts.signals
