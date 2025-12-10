from django.views.generic import ListView, View, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse_lazy
from django.contrib import messages
from .models import Task
from .forms import TaskForm
from accounts.models import Profile

class DashboardView(LoginRequiredMixin, ListView):
    model = Task
    template_name = "todo/dashboard.html"
    context_object_name = "tasks"
    paginate_by = 5
    
    def get_queryset(self):
        # Task.author is a Profile, not User. Fetch the profile first.
        profile = get_object_or_404(Profile, user=self.request.user)
        return Task.objects.filter(author=profile).prefetch_related('assignments').order_by('-created_date')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_tasks = self.get_queryset()
        context['tasks_total'] = user_tasks.count()
        context['tasks_completed'] = user_tasks.filter(completed=True).count()
        return context

class TaskCreateView(LoginRequiredMixin, CreateView):
    model = Task
    fields = ['title']
    success_url = reverse_lazy("todo:dashboard")
    
    def form_valid(self, form):
        # Assign the profile instance, not the user instance
        profile = get_object_or_404(Profile, user=self.request.user)
        form.instance.author = profile
        messages.success(self.request, "Task created successfully!")
        return super().form_valid(form)

class TaskToggleView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        profile = get_object_or_404(Profile, user=request.user)
        task = get_object_or_404(Task, pk=kwargs['pk'], author=profile)
        task.completed = not task.completed
        task.save()
        return redirect('todo:dashboard')

class TaskDeleteView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        profile = get_object_or_404(Profile, user=request.user)
        task = get_object_or_404(Task, pk=kwargs['pk'], author=profile)
        task.delete()
        messages.success(request, "Task deleted.")
        return redirect('todo:dashboard')
