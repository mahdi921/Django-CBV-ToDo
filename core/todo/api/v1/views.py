from rest_framework import viewsets
from .serializers import TaskSerializer, AssignmentSerializer
from todo.models import Task, Assignment
from rest_framework.permissions import IsAuthenticated
from .permissions import IsOwnerOrReadOnly


class TaskModelViewSet(viewsets.ModelViewSet):
    model = Task
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]

    def get_queryset(self):
        return self.model.objects.filter(author=self.request.user.id)


class AssignmentModelViewSet(viewsets.ModelViewSet):
    """ViewSet for Assignment CRUD operations"""
    model = Assignment
    serializer_class = AssignmentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Only return assignments for tasks owned by the current user
        return self.model.objects.filter(task__author__user=self.request.user)

    def perform_create(self, serializer):
        # Ensure the task belongs to the current user before creating assignment
        task_id = self.request.data.get('task')
        task = Task.objects.filter(id=task_id, author__user=self.request.user).first()
        if task:
            serializer.save(task=task)
        else:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You don't have permission to add assignments to this task")
