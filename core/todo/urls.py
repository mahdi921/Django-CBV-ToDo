from django.urls import path, include
from todo import views
from django.views.generic.base import RedirectView

app_name = 'todo'

urlpatterns = [
    path("", RedirectView.as_view(url='/tasks/'), name="index"),
    path("tasks/", views.TaskList.as_view(), name="task-list"),
    path("tasks/create/", views.TaskCreateView.as_view(), name='task-create'),
    path('tasks/<int:pk>/edit/',
         views.TaskEditView.as_view(), name='task-edit'),
    path('tasks/<int:pk>/delete/',
         views.TaskDeleteView.as_view(), name='task-delete'),
    path('tasks/api/v1/', include('todo.api.v1.urls')),
]
