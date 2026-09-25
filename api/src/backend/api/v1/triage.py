"""Triage API contracts used by the finding tables and detail drawers."""

from api.base_views import BaseRLSViewSet
from api.models import FindingTriage, FindingTriageEvent, FindingTriageNote
from api.rbac.permissions import get_providers, get_role
from api.triage import (
    MANUAL_STATUSES,
    confirm_resource_removal,
    resolve_finding,
    update_triage,
    visible_findings,
)
from api.triage_tracking import tracked_triages
from api.v1.serializers import RLSSerializer
from django.conf import settings
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response
from rest_framework_json_api import serializers


class TriageSerializer(RLSSerializer):
    notes_count = serializers.SerializerMethodField()
    provider_id = serializers.UUIDField(read_only=True)

    def get_notes_count(self, obj) -> int:
        if hasattr(obj, "notes_count"):
            return obj.notes_count
        return FindingTriageNote.objects.filter(
            tenant_id=obj.tenant_id, triage=obj
        ).count()

    class Meta:
        model = FindingTriage
        fields = [
            "id",
            "finding_uid",
            "provider_id",
            "status",
            "resolution_reason",
            "notes_count",
            "inserted_at",
            "updated_at",
        ]
        read_only_fields = fields

    class JSONAPIMeta:
        resource_name = "finding-triages"


class TrackedTriageSerializer(TriageSerializer):
    provider_alias = serializers.CharField(
        source="provider.alias", read_only=True, allow_null=True
    )
    provider_type = serializers.CharField(source="provider.provider", read_only=True)
    can_edit = serializers.SerializerMethodField()
    can_manage_exceptions = serializers.SerializerMethodField()

    def _role(self):
        if "_triage_role" not in self.context:
            request = self.context["request"]
            self.context["_triage_role"] = get_role(request.user, request.tenant_id)
        return self.context["_triage_role"]

    def get_can_edit(self, obj) -> bool:
        return self._role().manage_triage

    def get_can_manage_exceptions(self, obj) -> bool:
        return self._role().manage_triage and self._role().manage_triage_exceptions

    class Meta(TriageSerializer.Meta):
        fields = TriageSerializer.Meta.fields + [
            "snapshot",
            "observation",
            "observation_detail",
            "observation_scan_id",
            "verification_checked_at",
            "provider_alias",
            "provider_type",
            "can_edit",
            "can_manage_exceptions",
        ]
        read_only_fields = fields


class TriageWriteSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=sorted(MANUAL_STATUSES), required=False)
    previous_status = serializers.ChoiceField(
        choices=FindingTriage.Status.choices, required=False
    )
    note = serializers.CharField(max_length=500, allow_blank=True, required=False)
    reason = serializers.CharField(max_length=500, min_length=3, required=False)
    confirm_mute = serializers.BooleanField(required=False, default=False)

    class JSONAPIMeta:
        resource_name = "finding-triages"

    def validate(self, attrs):
        unknown = set(self.initial_data) - set(self.fields) - {"id", "type"}
        if unknown:
            raise ValidationError(dict.fromkeys(sorted(unknown), "Unknown field."))
        if "status" not in attrs and "note" not in attrs:
            raise ValidationError("Provide a triage status or note.")
        return attrs


class TriageNoteSerializer(RLSSerializer):
    body = serializers.CharField(max_length=500, allow_blank=False)

    class JSONAPIMeta:
        resource_name = "finding-triage-notes"

    class Meta:
        model = FindingTriageNote
        fields = ["id", "body", "inserted_at", "updated_at"]
        read_only_fields = ["id", "inserted_at", "updated_at"]


class RemovalConfirmationSerializer(serializers.Serializer):
    previous_status = serializers.ChoiceField(choices=FindingTriage.Status.choices)
    observation_scan_id = serializers.UUIDField()
    finding_id = serializers.UUIDField()
    evidence = serializers.CharField(min_length=3, max_length=500, allow_blank=False)
    confirm_removed = serializers.BooleanField()

    class JSONAPIMeta:
        resource_name = "finding-triages"

    def validate(self, attrs):
        unknown = set(self.initial_data) - set(self.fields) - {"id", "type"}
        if unknown:
            raise ValidationError(dict.fromkeys(sorted(unknown), "Unknown field."))
        return attrs


class TriageEventSerializer(RLSSerializer):
    class JSONAPIMeta:
        resource_name = "finding-triage-events"

    actor_name = serializers.SerializerMethodField()

    def get_actor_name(self, obj) -> str:
        if obj.actor:
            return obj.actor.name or obj.actor.email
        return (
            "Scan"
            if obj.kind == "scan"
            else "Resource verification"
            if obj.kind == "verification"
            else "Deleted user"
        )

    class Meta:
        model = FindingTriageEvent
        fields = ["id", "kind", "changes", "actor_name", "scan_id", "inserted_at"]
        read_only_fields = fields


class FindingTriageViewSet(BaseRLSViewSet):
    queryset = FindingTriage.objects.all()
    serializer_class = TriageSerializer
    http_method_names = ["get", "patch", "delete", "head", "options"]
    filter_backends = []
    filterset_class = None

    def initial(self, request, *args, **kwargs):
        self.lookup_url_kwarg = (
            "note_id"
            if "note_id" in kwargs
            else "finding_uid"
            if "finding_uid" in kwargs
            else "pk"
        )
        super().initial(request, *args, **kwargs)
        if not settings.VRIKA_TRIAGE_ENABLED:
            raise NotFound("Finding triage is not enabled.")

    def get_queryset(self):
        role = get_role(self.request.user, self.request.tenant_id)
        queryset = FindingTriage.objects.filter(
            tenant_id=self.request.tenant_id, provider__is_deleted=False
        )
        if not role.unlimited_visibility:
            queryset = queryset.filter(provider__in=get_providers(role))
        return queryset.order_by("id")

    def get_serializer_class(self):
        if self.action == "tracked":
            return TrackedTriageSerializer
        if self.action in {"notes", "update_note", "delete_note"}:
            return TriageNoteSerializer
        if self.action == "history":
            return TriageEventSerializer
        return self.serializer_class

    @extend_schema(responses=TrackedTriageSerializer(many=True))
    @action(detail=False, methods=["get"])
    def tracked(self, request, *args, **kwargs):
        queryset = (
            tracked_triages(self.get_queryset())
            .select_related("provider")
            .annotate(notes_count=Count("note"))
        )
        status_filter = request.query_params.get("filter[status]")
        if status_filter:
            if status_filter not in FindingTriage.Status.values:
                raise ValidationError("Invalid triage status.")
            queryset = queryset.filter(status=status_filter)
        provider_id = request.query_params.get("filter[provider_id]")
        if provider_id:
            from uuid import UUID

            try:
                provider_id = UUID(provider_id)
            except ValueError:
                raise ValidationError("Invalid provider ID.")
            queryset = queryset.filter(provider_id=provider_id)
        search = request.query_params.get("filter[search]", "").strip()
        if len(search) > 200:
            raise ValidationError("Search cannot exceed 200 characters.")
        if search:
            queryset = queryset.filter(
                Q(finding_uid__icontains=search)
                | Q(snapshot__title__icontains=search)
                | Q(snapshot__resources__icontains=search)
            )
        queryset = queryset.order_by("-updated_at", "-id")
        page = self.paginate_queryset(queryset)
        if page is None:
            return Response(self.get_serializer(queryset, many=True).data)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    def _target(self):
        if "finding_uid" in self.kwargs:
            finding = resolve_finding(self.request, self.kwargs["finding_uid"])
            triage = (
                self.get_queryset()
                .filter(provider_id=finding.scan.provider_id, finding_uid=finding.uid)
                .first()
            )
        else:
            triage = get_object_or_404(self.get_queryset(), id=self.kwargs["pk"])
            finding = (
                visible_findings(self.request)
                .filter(uid=triage.finding_uid, scan__provider_id=triage.provider_id)
                .select_related("scan")
                .order_by("-id")
                .first()
            )
        return finding, triage

    @extend_schema(
        request=RemovalConfirmationSerializer, responses={200: TriageSerializer}
    )
    @action(detail=True, methods=["patch"], url_path="confirm-removal")
    def confirm_removal(self, request, *args, **kwargs):
        triage = self.get_object()
        payload = RemovalConfirmationSerializer(data=request.data)
        payload.is_valid(raise_exception=True)
        triage = confirm_resource_removal(request, triage, payload.validated_data)
        return Response(
            TriageSerializer(triage, context=self.get_serializer_context()).data
        )

    @extend_schema(request=TriageWriteSerializer, responses={200: TriageSerializer})
    def partial_update(self, request, *args, **kwargs):
        finding, existing = self._target()
        payload = TriageWriteSerializer(data=request.data)
        payload.is_valid(raise_exception=True)
        triage = update_triage(
            request, finding, payload.validated_data, triage=existing
        )
        return Response(self.get_serializer(triage).data)

    @extend_schema(responses=TriageNoteSerializer(many=True))
    def notes(self, request, *args, **kwargs):
        _, triage = self._target()
        queryset = (
            FindingTriageNote.objects.filter(tenant_id=request.tenant_id, triage=triage)
            if triage
            else FindingTriageNote.objects.none()
        )
        return Response(self.get_serializer(queryset, many=True).data)

    @extend_schema(request=TriageNoteSerializer, responses=TriageNoteSerializer)
    def update_note(self, request, *args, **kwargs):
        finding, triage = self._target()
        if triage is None:
            raise NotFound("Triage note not found.")
        note = get_object_or_404(
            FindingTriageNote,
            id=kwargs["note_id"],
            tenant_id=request.tenant_id,
            triage=triage,
        )
        payload = TriageNoteSerializer(data=request.data)
        payload.is_valid(raise_exception=True)
        update_triage(
            request,
            finding,
            {"note": payload.validated_data["body"]},
            note_id=note.id,
            triage=triage,
        )
        note.refresh_from_db()
        return Response(self.get_serializer(note).data)

    @extend_schema(responses={204: None})
    def delete_note(self, request, *args, **kwargs):
        finding, triage = self._target()
        if triage is None:
            raise NotFound("Triage note not found.")
        update_triage(
            request, finding, {"note": ""}, note_id=kwargs["note_id"], triage=triage
        )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(responses=TriageEventSerializer(many=True))
    def history(self, request, *args, **kwargs):
        _, triage = self._target()
        queryset = (
            FindingTriageEvent.objects.filter(
                tenant_id=request.tenant_id, triage=triage
            ).select_related("actor")
            if triage
            else FindingTriageEvent.objects.none()
        )
        page = self.paginate_queryset(queryset)
        if page is None:
            return Response(self.get_serializer(queryset, many=True).data)
        return self.get_paginated_response(self.get_serializer(page, many=True).data)

    def destroy(self, request, *args, **kwargs):
        from rest_framework.exceptions import MethodNotAllowed

        raise MethodNotAllowed("DELETE")
