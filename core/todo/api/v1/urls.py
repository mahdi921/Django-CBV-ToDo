from . import views
from rest_framework.routers import DefaultRouter

app_name = "api-v1"

router = DefaultRouter()
router.register("task", views.TaskModelViewSet, basename="task")
router.register("assignment", views.AssignmentModelViewSet, basename="assignment")

urlpatterns = router.urls
