import pytest
from rest_framework.test import APIClient
from django.urls import reverse
from accounts.models import User


@pytest.fixture
def common_user():
    user = User.objects.create_user(
        email="test@test.com", password="123456789Ab.", is_verified=True
    )
    return user


@pytest.fixture
def api_client():
    client = APIClient()
    return client


@pytest.mark.django_db
class TestAccountsAPI:
    def test_get_registration_url_auth_response_403(self, api_client, common_user):
        url = reverse("accounts:api-v1:register")
        user = common_user
        response = api_client.force_authenticate(user=user)
        response = api_client.get(url)
        assert response.status_code == 403

    def test_get_registration_url_unauth_response_405(self, api_client):
        url = reverse("accounts:api-v1:register")
        response = api_client.get(url)
        assert response.status_code == 405
