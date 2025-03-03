from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from accounts.models import User, Profile

admin.site.register(Profile)


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ["email", "is_superuser", "is_active"]
    list_filter = ["email", "is_superuser", "is_active"]
    search_fields = ["email"]
    ordering = ["email"]
    filter_horizontal = []
    fieldsets = (
        ("Authentication", {"fields": ("email", "password")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_superuser",
                    "is_staff",
                    "is_active",
                )
            },
        ),
        ("Group Permissions", {"fields": ("groups", "user_permissions")}),
        ("Important Dates", {"fields": ("last_login",)}),
    )
    # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "is_superuser",
                    "is_staff",
                    "is_active",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
    )
