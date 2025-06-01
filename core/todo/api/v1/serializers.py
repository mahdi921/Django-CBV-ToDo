from rest_framework import serializers
from todo.models import Task
from accounts.models import Profile


class TaskSerializer(serializers.ModelSerializer):
    relative_url = serializers.URLField(
        source="get_absolute_api_url",
        read_only=True
        )
    absolute_url = serializers.SerializerMethodField()

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
        ]
        read_only_fields = ("author",)

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
