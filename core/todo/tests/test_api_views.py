import pytest
from rest_framework.test import APIClient
from django.urls import reverse
from accounts.models import User


@pytest.fixture
def api_client():
    client = APIClient()
    return client


@pytest.fixture
def common_user():
    user = User.objects.create_user(
        email='test@test.com',
        password='Testpassword123.',
        is_verified=True
    )
    return user


@pytest.mark.django_db
class TestTasksAPI:
    data = {
        'title': 'test task',
        'completed': False
    }

    def test_get_tasks_list_unauthenticated(self, api_client):
        url = reverse("todo:api-v1:task-list")
        response = api_client.get(url)
        assert response.status_code == 401

    def test_get_tasks_list_authenticated(self, api_client, common_user):
        url = reverse("todo:api-v1:task-list")
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.get(url)
        assert response.status_code == 200

    def test_post_tasks_create_response_201(self, api_client, common_user):
        url = reverse('todo:api-v1:task-list')
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.post(url, self.data)
        assert response.status_code == 201

    def test_put_tasks_edit_response_200(self, api_client, common_user):
        url = reverse('todo:api-v1:task-list')
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.post(url, self.data)
        data = {
            'title': 'testing task',
            'completed': True
        }
        url = reverse('todo:api-v1:task-detail', kwargs={'pk': 1})
        response = api_client.put(url, data)
        assert response.status_code == 200

    def test_delete_tasks_delete_response_204(self, api_client, common_user):
        url = reverse('todo:api-v1:task-list')
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.post(url, self.data)
        url = reverse('todo:api-v1:task-detail', kwargs={'pk': 1})
        response = api_client.delete(url)
        assert response.status_code == 204

    def test_get_task_detail_response_unauth_401(self, api_client):
        url = reverse('todo:api-v1:task-detail', kwargs={'pk': 1})
        response = api_client.get(url)
        assert response.status_code == 401
