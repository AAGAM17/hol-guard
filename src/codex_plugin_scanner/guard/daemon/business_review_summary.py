"""Authenticated local review-detail route, separate from Cloud projection."""

from urllib.parse import unquote

from ..runtime.native_business_review_summary import read_native_business_review_summary


def handle_business_review_summary(handler, request_id: str) -> None:
    summary = read_native_business_review_summary(handler.server.store.guard_home, unquote(request_id))
    handler._write_json(
        summary if summary is not None else {"error": "native_local_business_summary_unavailable"},
        status=200 if summary is not None else 404,
        extra_headers={"Cache-Control": "no-store"},
    )
