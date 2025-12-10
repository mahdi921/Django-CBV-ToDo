from rest_framework import serializers
from todo.models import Task, Assignment
from accounts.models import Profile


class AssignmentSerializer(serializers.ModelSerializer):
    """Serializer for Assignment model"""
    class Meta:
        model = Assignment
        fields = [
            "id",
            "description",
            "completed",
            "created_at",
            "updated_at",
            "order",
        ]
        read_only_fields = ("created_at", "updated_at")


class TaskSerializer(serializers.ModelSerializer):
    relative_url = serializers.URLField(source="get_absolute_api_url", read_only=True)
    absolute_url = serializers.SerializerMethodField()
    assignments = AssignmentSerializer(many=True, read_only=True)

    class Meta:
        model = Task
        fields = [
            "id",
            "author",
            "title",
            "completed",
            "created_date",
            "updated_date",
            "relative_url",
            "absolute_url",
            "assignments",
        ]
        read_only_fields = ("author", "created_date", "updated_date")

    def create(self, validated_data):
        validated_data["author"] = Profile.objects.get(
            user__id=self.context.get("request").user.id
        )
        return super().create(validated_data)

    def get_absolute_url(self, obj):
        request = self.context.get("request")
        return request.build_absolute_uri(obj.pk)

    def to_representation(self, instance):
        request = self.context.get("request")
        represntation = super().to_representation(instance)
        if request.parser_context.get("kwargs").get("pk"):
            represntation.pop("relative_url", None)
            represntation.pop("absolute_url", None)
        return represntation
