from __future__ import annotations

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request, UploadFile, status
from fastapi.responses import RedirectResponse, Response

from app.api.deps import ClientDep, CurrentUser, FileServiceDep, ResourcesDep
from app.models import AccessLevel, ShareLink
from app.schemas.files import (
    DirectUploadOut,
    DirectUploadRequest,
    DownloadUrl,
    FileOut,
    FileRename,
    GrantOut,
    GrantRequest,
    ShareLinkCreate,
    ShareLinkCreated,
    ShareLinkOut,
)
from app.services.files import FileWithAccess, GrantWithEmail

router = APIRouter(prefix="/files", tags=["files"])
public_router = APIRouter(tags=["share links"])


def _file_out(fa: FileWithAccess) -> FileOut:
    return FileOut.model_validate({**_columns(fa.file), "access": fa.access})


def _columns(obj: object) -> dict[str, object]:
    return {k: v for k, v in vars(obj).items() if not k.startswith("_")}


def _grant_out(g: GrantWithEmail) -> GrantOut:
    return GrantOut.model_validate({**_columns(g.grant), "email": g.email})


@router.post("", response_model=FileOut, status_code=status.HTTP_201_CREATED)
async def upload_file(upload: UploadFile, user: CurrentUser, files: FileServiceDep) -> FileOut:
    record = await files.upload(
        user, upload.file, filename=upload.filename, content_type=upload.content_type
    )
    return _file_out(FileWithAccess(record, AccessLevel.OWNER))


@router.post("/uploads", response_model=DirectUploadOut, status_code=status.HTTP_201_CREATED)
async def start_direct_upload(
    body: DirectUploadRequest, request: Request, user: CurrentUser, files: FileServiceDep
) -> DirectUploadOut:
    """Get a presigned POST so the client uploads straight to S3, bypassing the API."""
    started = await files.start_direct_upload(
        user,
        filename=body.filename,
        content_type=body.content_type,
        size_bytes=body.size_bytes,
        sha256=body.sha256,
    )
    return DirectUploadOut(
        upload_id=started.intent.id,
        url=started.post.url,
        fields=started.post.fields,
        expires_at=started.intent.expires_at,
        complete_url=str(
            request.url_for("complete_direct_upload", upload_id=str(started.intent.id))
        ),
    )


@router.post(
    "/uploads/{upload_id}/complete",
    name="complete_direct_upload",
    response_model=FileOut,
    status_code=status.HTTP_201_CREATED,
)
async def complete_direct_upload(
    upload_id: uuid.UUID, user: CurrentUser, files: FileServiceDep
) -> FileOut:
    record = await files.complete_direct_upload(user, upload_id)
    return _file_out(FileWithAccess(record, AccessLevel.OWNER))


@router.get("", response_model=list[FileOut])
async def list_files(
    user: CurrentUser,
    files: FileServiceDep,
    scope: Literal["owned", "shared", "all"] = "all",
) -> list[FileOut]:
    return [_file_out(fa) for fa in await files.list_for(user, scope)]


@router.get("/{file_id}", response_model=FileOut)
async def get_file(file_id: uuid.UUID, user: CurrentUser, files: FileServiceDep) -> FileOut:
    return _file_out(await files.get_for(user, file_id, AccessLevel.VIEWER))


@router.patch("/{file_id}", response_model=FileOut)
async def rename_file(
    file_id: uuid.UUID, body: FileRename, user: CurrentUser, files: FileServiceDep
) -> FileOut:
    return _file_out(await files.rename(user, file_id, body.filename))


@router.delete("/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(file_id: uuid.UUID, user: CurrentUser, files: FileServiceDep) -> Response:
    await files.delete(user, file_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{file_id}/download", response_model=DownloadUrl)
async def download_url(
    file_id: uuid.UUID,
    user: CurrentUser,
    files: FileServiceDep,
    ttl: Annotated[
        int | None, Query(ge=10, description="Seconds; clamped to the server max")
    ] = None,
) -> DownloadUrl:
    url, expires_at = await files.download_url(user, file_id, ttl)
    return DownloadUrl(url=url, expires_at=expires_at)


# --- per-user grants -------------------------------------------------------------------
@router.post("/{file_id}/permissions", response_model=GrantOut, status_code=status.HTTP_201_CREATED)
async def grant_permission(
    file_id: uuid.UUID, body: GrantRequest, user: CurrentUser, files: FileServiceDep
) -> GrantOut:
    grant = await files.grant(
        user,
        file_id,
        email=body.email,
        level=body.level,
        expires_in_seconds=body.expires_in_seconds,
    )
    return _grant_out(grant)


@router.get("/{file_id}/permissions", response_model=list[GrantOut])
async def list_permissions(
    file_id: uuid.UUID, user: CurrentUser, files: FileServiceDep
) -> list[GrantOut]:
    return [_grant_out(g) for g in await files.list_grants(user, file_id)]


@router.delete("/{file_id}/permissions/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_permission(
    file_id: uuid.UUID, user_id: uuid.UUID, user: CurrentUser, files: FileServiceDep
) -> Response:
    await files.revoke_grant(user, file_id, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- share links -----------------------------------------------------------------------
def _link_out(link: ShareLink) -> ShareLinkOut:
    return ShareLinkOut.model_validate(link)


@router.post(
    "/{file_id}/links", response_model=ShareLinkCreated, status_code=status.HTTP_201_CREATED
)
async def create_share_link(
    file_id: uuid.UUID,
    body: ShareLinkCreate,
    request: Request,
    user: CurrentUser,
    files: FileServiceDep,
) -> ShareLinkCreated:
    link, token = await files.create_link(
        user, file_id, expires_in_seconds=body.expires_in_seconds, max_downloads=body.max_downloads
    )
    url = str(request.url_for("redeem_share_link", token=token))
    return ShareLinkCreated.model_validate({**_columns(link), "token": token, "url": url})


@router.get("/{file_id}/links", response_model=list[ShareLinkOut])
async def list_share_links(
    file_id: uuid.UUID, user: CurrentUser, files: FileServiceDep
) -> list[ShareLinkOut]:
    return [_link_out(link) for link in await files.list_links(user, file_id)]


@router.delete("/{file_id}/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_share_link(
    file_id: uuid.UUID, link_id: uuid.UUID, user: CurrentUser, files: FileServiceDep
) -> Response:
    await files.revoke_link(user, file_id, link_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _throttle_share_links(client: ClientDep, resources: ResourcesDep) -> None:
    s = resources.settings
    await resources.limiter.enforce(
        f"share:ip:{client.ip_address}",
        limit=s.share_link_max_hits_per_ip,
        window_seconds=s.share_link_window_seconds,
    )


@public_router.get(
    "/s/{token}",
    name="redeem_share_link",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    dependencies=[Depends(_throttle_share_links)],
    responses={307: {"description": "Redirect to a short-lived presigned download URL"}},
)
async def redeem_share_link(token: str, files: FileServiceDep) -> RedirectResponse:
    url = await files.redeem_link(token)
    return RedirectResponse(
        url,
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )
