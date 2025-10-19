from rest_framework import viewsets
from .serializers import TaskSerializer
from todo.models import Task
from rest_framework.permissions import IsAuthenticated
from .permissions import IsOwnerOrReadOnly


class TaskModelViewSet(viewsets.ModelViewSet):
    model = Task
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]

    def get_queryset(self):
        return self.model.objects.filter(author=self.request.user.id)
