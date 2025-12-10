from django.urls import path, include
from todo import views

app_name = "todo"

urlpatterns = [
    # Dashboard (Root URL)
    path("dashboard/", views.DashboardView.as_view(), name="dashboard"),
    
    # Redirect root to dashboard (handled by core.urls usually, but for app isolation)
    path("", views.DashboardView.as_view(), name="index"),
    
    # Task Actions
    path("tasks/create/", views.TaskCreateView.as_view(), name="task-create"),
    path("tasks/toggle/<int:pk>/", views.TaskToggleView.as_view(), name="task-toggle"),
    path("tasks/delete/<int:pk>/", views.TaskDeleteView.as_view(), name="task-delete"),
    
    # API Patterns
    path("tasks/api/v1/", include("todo.api.v1.urls")),
]
