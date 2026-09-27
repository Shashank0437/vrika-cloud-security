from api.rbac.vrika_sync import resolve_provider_projects, sync_access, verify_bridge
from drf_spectacular.utils import extend_schema
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView


class BridgeParser(JSONParser):
    media_type = "application/vnd.api+json"


class BridgeRenderer(JSONRenderer):
    media_type = "application/vnd.api+json"


class VrikaAccessSyncView(APIView):
    authentication_classes = ()
    permission_classes = ()
    parser_classes = (BridgeParser,)
    renderer_classes = (BridgeRenderer,)

    @extend_schema(
        tags=["Internal"],
        summary="Synchronize signed Vrika role bindings",
        request={"application/vnd.api+json": {"type": "object"}},
        responses={200: {"type": "object"}},
    )
    def post(self, request):
        verify_bridge(request)
        result = sync_access(request.data)
        return Response(
            {"data": {"type": "vrika-access", "id": "sync", "attributes": result}}
        )


class VrikaProviderProjectsView(APIView):
    authentication_classes = ()
    permission_classes = ()
    parser_classes = (BridgeParser,)
    renderer_classes = (BridgeRenderer,)

    @extend_schema(
        tags=["Internal"],
        summary="Resolve a provider's current project assignments",
        request={"application/vnd.api+json": {"type": "object"}},
        responses={200: {"type": "object"}},
    )
    def post(self, request):
        verify_bridge(request)
        result = resolve_provider_projects(request.data)
        return Response(
            {"data": {"type": "vrika-provider-projects", "id": result["provider_id"],
                      "attributes": result}}
        )
